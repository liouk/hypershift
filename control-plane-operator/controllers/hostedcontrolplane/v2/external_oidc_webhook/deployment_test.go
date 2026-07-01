package extoidc

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"

	hyperv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/v2/assets"
	"github.com/openshift/hypershift/support/api"
	"github.com/openshift/hypershift/support/config"
	component "github.com/openshift/hypershift/support/controlplane-component"
	"github.com/openshift/hypershift/support/podspec"

	configv1 "github.com/openshift/api/config/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAdaptDeployment(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		profile *configv1.TLSSecurityProfile
	}{
		{
			name: "When the default TLS profile is used, it should configure the expected TLS arguments",
		},
		{
			name: "When the modern TLS profile is used, it should configure the expected TLS arguments",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewWithT(t)

			deployment, err := assets.LoadDeploymentManifest(ComponentName)
			g.Expect(err).ToNot(HaveOccurred())

			hcp := &hyperv1.HostedControlPlane{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-hcp",
					Namespace: "test-ns",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					Configuration: &hyperv1.ClusterConfiguration{
						APIServer: &configv1.APIServerSpec{
							TLSSecurityProfile: tc.profile,
						},
					},
				},
			}

			cpContext := component.WorkloadContext{
				Client: fake.NewClientBuilder().WithScheme(api.Scheme).Build(),
				HCP:    hcp,
			}
			g.Expect(adaptDeployment(cpContext, deployment)).To(Succeed())

			container := podspec.FindContainer(ComponentName, deployment.Spec.Template.Spec.Containers)
			g.Expect(container).ToNot(BeNil())

			expectedMinTLSVersion, err := config.MinTLSVersion(hcp.Spec.Configuration.GetTLSSecurityProfile())
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(container.Args).To(ContainElement(fmt.Sprintf("--tls-min-version=%s", expectedMinTLSVersion)))

			expectedCipherSuites, err := config.CipherSuites(hcp.Spec.Configuration.GetTLSSecurityProfile())
			g.Expect(err).ToNot(HaveOccurred())
			for _, cipherSuite := range expectedCipherSuites {
				g.Expect(container.Args).To(ContainElement(fmt.Sprintf("--tls-cipher-suites=%s", cipherSuite)))
			}
		})
	}
}
