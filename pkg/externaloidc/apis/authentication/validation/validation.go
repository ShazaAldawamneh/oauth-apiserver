package validation

import (
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/conversion"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

func ValidateAuthenticationConfiguration(compiler authenticationcel.Compiler, c *authentication.AuthenticationConfiguration) field.ErrorList {
	errors := field.ErrorList{}

	root := field.NewPath("jwt")

	// Unlike the kube-apiserver, we require that there be at least one authenticator defined.
	if len(c.JWT) == 0 {
		errors = append(errors, field.Required(root, "jwt is required and must not be empty"))
	}

	// defer to kube-apiserver validation
	errors = append(errors,
		validation.ValidateAuthenticationConfiguration(
			compiler,
			conversion.ConvertAuthenticationConfigurationToApiserverAuthenticationConfiguration(c),
			nil,
		)...)

	return errors
}
