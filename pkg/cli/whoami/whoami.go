package whoami

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	userv1 "github.com/openshift/api/user/v1"
	userv1typedclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"

	v1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	clientauthenticationapi "k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/plugin/pkg/client/auth/exec"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"
	kcmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/templates"
)

const (
	openShiftConfigManagedNamespaceName = "openshift-config-managed"
	consolePublicConfigMap              = "console-public"
)

var whoamiLong = templates.LongDesc(`
	Show information about the current session

	The default options for this command will return the currently authenticated user name
	or an empty string.  Other flags support returning the currently used token or the
	user context.`)

var whoamiExample = templates.Examples(`
	# Display the currently authenticated user
	oc whoami
`)

type WhoAmIOptions struct {
	UserInterface userv1typedclient.UserV1Interface
	AuthV1Client  authenticationv1client.AuthenticationV1Interface

	ClientConfig *rest.Config
	KubeClient   kubernetes.Interface
	RawConfig    api.Config

	ShowToken      bool
	ShowContext    bool
	ShowServer     bool
	ShowConsoleUrl bool

	// resolvedToken holds the bearer token resolved during Validate(), which may
	// come directly from the kubeconfig AuthInfo or, when the current context
	// uses an exec-based credential plugin, from invoking that plugin.
	resolvedToken string

	PrintFlags          *genericclioptions.PrintFlags
	resourcePrinterFunc printers.ResourcePrinterFunc

	genericiooptions.IOStreams
}

func NewWhoAmIOptions(streams genericiooptions.IOStreams) *WhoAmIOptions {
	return &WhoAmIOptions{
		PrintFlags: genericclioptions.NewPrintFlags("").WithTypeSetter(scheme.Scheme),
		IOStreams:  streams,
	}
}

func NewCmdWhoAmI(f kcmdutil.Factory, streams genericiooptions.IOStreams) *cobra.Command {
	o := NewWhoAmIOptions(streams)

	cmd := &cobra.Command{
		Use:     "whoami",
		Short:   "Return information about the current session",
		Long:    whoamiLong,
		Example: whoamiExample,
		Run: func(cmd *cobra.Command, args []string) {
			kcmdutil.CheckErr(o.Complete(f))
			kcmdutil.CheckErr(o.Validate())
			kcmdutil.CheckErr(o.Run())
		},
	}

	cmd.Flags().BoolVarP(&o.ShowToken, "show-token", "t", o.ShowToken, "Print the token the current session is using. This will return an error if you are using a different form of authentication.")
	cmd.Flags().BoolVarP(&o.ShowContext, "show-context", "c", o.ShowContext, "Print the current user context name")
	cmd.Flags().BoolVar(&o.ShowServer, "show-server", o.ShowServer, "If true, print the current server's REST API URL")
	cmd.Flags().BoolVar(&o.ShowConsoleUrl, "show-console", o.ShowConsoleUrl, "If true, print the current server's web console URL")
	o.PrintFlags.AddFlags(cmd)

	return cmd
}

func (o WhoAmIOptions) WhoAmI() (*userv1.User, error) {
	res, err := o.AuthV1Client.SelfSubjectReviews().Create(context.TODO(), &v1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		me := &userv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Name: res.Status.UserInfo.Username,
			},
			Groups: res.Status.UserInfo.Groups,
		}
		if o.resourcePrinterFunc != nil {
			return me, o.resourcePrinterFunc(me, o.Out)
		}
		fmt.Fprintf(o.Out, "%s\n", me.Name)
		return me, nil
	} else {
		klog.V(2).Infof("selfsubjectreview request error %v, falling back to user object", err)
	}
	me, err := o.UserInterface.Users().Get(context.TODO(), "~", metav1.GetOptions{})
	if err == nil {
		if o.resourcePrinterFunc != nil {
			return me, o.resourcePrinterFunc(me, o.Out)
		}
		fmt.Fprintf(o.Out, "%s\n", me.Name)
	}

	return me, err
}

func (o *WhoAmIOptions) Complete(f kcmdutil.Factory) error {
	var err error

	o.ClientConfig, err = f.ToRESTConfig()
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(o.ClientConfig)
	if err != nil {
		return err
	}
	o.KubeClient = kubeClient

	o.RawConfig, err = f.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}
	if o.PrintFlags.OutputFlagSpecified() {
		printer, err := o.PrintFlags.ToPrinter()
		if err != nil {
			return err
		}
		o.resourcePrinterFunc = printer.PrintObj
	}
	return nil
}

func (o *WhoAmIOptions) Validate() error {
	if o.PrintFlags.OutputFlagSpecified() && (o.ShowToken || o.ShowContext || o.ShowServer || o.ShowConsoleUrl) {
		return fmt.Errorf("--output cannot be used with --show-token, --show-context, --show-server, or --show-console")
	}
	if o.ShowToken {
		token, err := resolveBearerToken(o.ClientConfig)
		if err != nil {
			return err
		}
		if len(token) == 0 {
			return fmt.Errorf("no token is currently in use for this session")
		}
		o.resolvedToken = token
	}
	if o.ShowContext && len(o.RawConfig.CurrentContext) == 0 {
		return fmt.Errorf("no context has been set")
	}
	return nil
}

// resolveBearerToken returns the bearer token that would be used to authenticate
// requests made with the given rest.Config. If the config carries a static
// token (AuthInfo.Token/TokenFile), that value is returned directly. If instead
// the current context authenticates via an exec-based credential plugin
// (AuthInfo.Exec, e.g. "oc login" OIDC helpers, cloud-provider IAM plugins,
// etc.), the plugin is invoked so its dynamically-issued token can be resolved
// and displayed. An empty string with a nil error means no token-based
// authentication is configured at all (e.g. client-cert auth).
func resolveBearerToken(restConfig *rest.Config) (string, error) {
	if len(restConfig.BearerToken) > 0 {
		return restConfig.BearerToken, nil
	}
	if len(restConfig.BearerTokenFile) > 0 {
		// rest.Config.WrapTransport / TransportConfig already reads BearerTokenFile
		// contents on each request; for display purposes it's populated into
		// BearerToken by clientcmd whenever TokenFile is set, so this branch is
		// effectively unreachable in practice but kept for completeness.
		return restConfig.BearerToken, nil
	}
	if restConfig.ExecProvider == nil {
		return "", nil
	}

	execConfig := restConfig.ExecProvider
	var cluster *clientauthenticationapi.Cluster
	if execConfig.ProvideClusterInfo {
		var err error
		cluster, err = rest.ConfigToExecCluster(restConfig)
		if err != nil {
			return "", fmt.Errorf("unable to resolve token from exec credential plugin: %v", err)
		}
	}

	authenticator, err := exec.GetAuthenticator(execConfig, cluster)
	if err != nil {
		return "", fmt.Errorf("unable to resolve token from exec credential plugin: %v", err)
	}

	// Drive the authenticator's RoundTripper against a no-op base transport so
	// we can capture the "Authorization: Bearer <token>" header it injects,
	// without making a real network call to the API server.
	transportConfig := &transport.Config{}
	if err := authenticator.UpdateTransportConfig(transportConfig); err != nil {
		return "", fmt.Errorf("unable to resolve token from exec credential plugin: %v", err)
	}

	capture := &capturingRoundTripper{}
	rt := transportConfig.WrapTransport(capture)

	req, err := http.NewRequest(http.MethodGet, restConfig.Host, nil)
	if err != nil {
		return "", fmt.Errorf("unable to resolve token from exec credential plugin: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		return "", fmt.Errorf("unable to resolve token from exec credential plugin: %v", err)
	}

	return strings.TrimPrefix(capture.authHeader, "Bearer "), nil
}

// capturingRoundTripper is a no-op http.RoundTripper that records the
// Authorization header set on the request it receives instead of performing
// any actual network I/O.
type capturingRoundTripper struct {
	authHeader string
}

func (c *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.authHeader = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}, nil
}

func (o *WhoAmIOptions) getWebConsoleUrl() (string, error) {
	consolePublicConfig, err := o.KubeClient.CoreV1().ConfigMaps(openShiftConfigManagedNamespaceName).Get(context.TODO(), consolePublicConfigMap, metav1.GetOptions{})
	// This means the command was run against 3.x server
	if errors.IsNotFound(err) {
		return o.ClientConfig.Host, nil
	}
	if err != nil {
		return "", fmt.Errorf("unable to determine console location: %v", err)
	}

	consoleUrl, exists := consolePublicConfig.Data["consoleURL"]
	if !exists {
		return "", fmt.Errorf("unable to determine console location from the cluster")
	}
	return consoleUrl, nil
}

func (o *WhoAmIOptions) Run() error {
	switch {
	case o.ShowToken:
		fmt.Fprintf(o.Out, "%s\n", o.resolvedToken)
		return nil
	case o.ShowContext:
		fmt.Fprintf(o.Out, "%s\n", o.RawConfig.CurrentContext)
		return nil
	case o.ShowServer:
		fmt.Fprintf(o.Out, "%s\n", o.ClientConfig.Host)
		return nil
	case o.ShowConsoleUrl:
		consoleUrl, err := o.getWebConsoleUrl()
		if err != nil {
			return err
		}
		fmt.Fprintf(o.Out, "%s\n", consoleUrl)
		return nil
	}

	var err error
	o.UserInterface, err = userv1typedclient.NewForConfig(o.ClientConfig)
	if err != nil {
		return err
	}

	o.AuthV1Client, err = authenticationv1client.NewForConfig(o.ClientConfig)
	if err != nil {
		return err
	}

	_, err = o.WhoAmI()
	return err
}
