package util

import (
	hyperv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"

	configv1 "github.com/openshift/api/config/v1"
)

func HCPOAuthEnabled(hcp *hyperv1.HostedControlPlane) bool {
	return oauthEnabled(hcp.Spec.Configuration)
}

func HCOAuthEnabled(hc *hyperv1.HostedCluster) bool {
	return oauthEnabled(hc.Spec.Configuration)
}

func HCPExternalOIDCEnabled(hcp *hyperv1.HostedControlPlane) bool {
	config := hcp.Spec.Configuration
	return config != nil && config.Authentication != nil && config.Authentication.Type == configv1.AuthenticationTypeOIDC
}

func ConfigOAuthEnabled(authentication *configv1.AuthenticationSpec) bool {
	if authentication != nil &&
		authentication.Type == configv1.AuthenticationTypeOIDC {
		return false
	}
	return true
}

func oauthEnabled(config *hyperv1.ClusterConfiguration) bool {
	if config != nil {
		return ConfigOAuthEnabled(config.Authentication)
	}
	return true
}
