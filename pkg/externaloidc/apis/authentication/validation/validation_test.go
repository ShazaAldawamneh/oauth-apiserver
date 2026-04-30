package validation_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/util/errors"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/utils/ptr"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/validation"
)

// NOTE: These test cases were taken from
// https://github.com/kubernetes/kubernetes/blob/03779bbd00da25c7fcd03711ddfe466a3322e1d7/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation_test.go#L46-L842
// and adjusted to fit our new configuration file API and validation pattern.

func TestValidateAuthenticationConfiguration(t *testing.T) {
	testCases := []struct {
		name string
		in   *authentication.AuthenticationConfiguration
		want string
	}{
		{
			name: "jwt authenticator is empty",
			in:   &authentication.AuthenticationConfiguration{},
			// NOTE: This differs from the upstream because this is an
			// opt-in feature from our end users and we do not allow them to
			// not specify any authentication configuration.
			// want: "",
			want: "jwt: Required value: jwt is required and must not be empty",
		},
		{
			name: "duplicate issuer across jwt authenticators",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[1].issuer.url: Duplicate value: "https://issuer-url"`,
		},
		{
			name: "duplicate discoveryURL across jwt authenticators",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:          "https://issuer-url",
							DiscoveryURL: "https://discovery-url/.well-known/openid-configuration",
							Audiences:    []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
					{
						Issuer: &authentication.Issuer{
							URL:          "https://different-issuer-url",
							DiscoveryURL: "https://discovery-url/.well-known/openid-configuration",
							Audiences:    []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[1].issuer.discoveryURL: Duplicate value: "https://discovery-url/.well-known/openid-configuration"`,
		},
		{
			name: "failed issuer validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "invalid-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[0].issuer.url: Invalid value: "invalid-url": URL scheme must be https`,
		},
		{
			name: "failed claimValidationRule validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
							{
								Claim:         "foo",
								RequiredValue: "baz",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[0].claimValidationRules[1].claim: Duplicate value: "foo"`,
		},
		{
			name: "failed claimMapping validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: "jwt[0].claimMappings.username: Required value: claim or expression is required",
		},
		{
			name: "failed userValidationRule validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						UserValidationRules: []authentication.UserValidationRule{
							{Expression: "user.username == 'foo'"},
							{Expression: "user.username == 'foo'"},
						},
					},
				},
			},
			want: `jwt[0].userValidationRules[1].expression: Duplicate value: "user.username == 'foo'"`,
		},
		{
			name: "valid authentication configuration with disallowed issuer",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			// TODO: We currently do not match the upstream on being able to configure disallowed issuers.
			// We should eventually match this functionality to ensure that we never attempt to
			// configure an authenticator for something like the service account issuer (what the disallowed issuers seems to be mostly used for upstream).
			// want: `jwt[0].issuer.url: Invalid value: "https://issuer-url": URL must not overlap with disallowed issuers: [a b c https://issuer-url]`,
			want: "",
		},
		{
			name: "valid authentication configuration that uses unverified email",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: "claims.email",
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "claims.email": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that almost uses unverified email",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: "claims.email_",
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses unverified email join",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "['yay', string(claims.email), 'panda'].join(' ')": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified optional email",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `claims.?email`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "claims.?email": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified optional map email key",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{claims.?email: "panda"}`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "{claims.?email: \"panda\"}": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified optional map email value",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{"fancy": claims.?email}`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "{\"fancy\": claims.?email}": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified email value in list iteration",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `["a"].map(i, i + claims.email)`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "[\"a\"].map(i, i + claims.email)": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses verified email join via rule",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Expression: `string(claims.email_verified) == "panda"`,
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email join via extra",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
							Extra: []authentication.ExtraMapping{
								{Key: "panda.io/foo", ValueExpression: "claims.email_verified.upperAscii()"},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email join via extra optional",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
							Extra: []authentication.ExtraMapping{
								{Key: "panda.io/foo", ValueExpression: "claims.?email_verified"},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses email and email_verified || true via username",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						// allow email claim when email_verified is true or absent
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `claims.?email_verified.orValue(true) ? claims.email : claims.sub`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses email and email_verified || false via username",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						// allow email claim only when email_verified is present and true
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `claims.?email_verified.orValue(false) ? claims.email : claims.sub`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email via claim validation rule",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								// By explicitly comparing the value to true, we let type-checking see the result will be
								// a boolean, and to make sure a non-boolean email_verified claim will be caught at runtime.
								Expression: `claims.?email_verified.orValue(true) == true`,
							},
						},
						// allow email claim only when email_verified is present and true
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{claims.?email: "panda"}`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email via claim validation rule incorrectly",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								// This expression was previously documented in the godoc for the JWT authenticator
								// and was incorrect. It was changed to the above expression in the previous test case.
								// Testing the old expression here to confirm it fails validation.
								Expression: `claims.?email_verified.orValue(true)`,
							},
						},
						// allow email claim only when email_verified is present and true
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{claims.?email: "panda"}`,
							},
						},
					},
				},
			},
			want: `[jwt[0].claimValidationRules[0].expression: Invalid value: "claims.?email_verified.orValue(true)": must evaluate to bool, jwt[0].claimMappings.username.expression: Invalid value: "{claims.?email: \"panda\"}": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression]`,
		},
		{
			name: "valid authentication configuration",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validation.ValidateAuthenticationConfiguration(authenticationcel.NewDefaultCompiler(), tt.in).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("AuthenticationConfiguration validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func errString(errs errors.Aggregate) string {
	if errs != nil {
		return errs.Error()
	}
	return ""
}
