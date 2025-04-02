package apikey

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizer_AvailableAPIKeys(t *testing.T) {
	type fields struct {
		SecretProvider              SecretProvider
		DeprecationExpirationPolicy DeprecationExpirationPolicy
		ReadOnly                    bool
	}

	t.Setenv("API_TOKEN_SECRET", "test-current-secret")
	t.Setenv("DEPRECATED_API_TOKEN_SECRET", "test-deprecated-current-secret")

	tests := []struct {
		name       string
		fields     fields
		httpMethod string
		want       []string
	}{
		{
			name: "deprecation policy is valid but deprecated key is not defined",
			fields: fields{
				SecretProvider: &EnvironmentSecretProvider{CurrentSecretHeaderName: "API_TOKEN_SECRET"},
				DeprecationExpirationPolicy: func() DeprecationExpirationPolicy {
					p, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(time.Minute).Format(time.RFC3339))
					require.NoError(t, err)
					return p
				}(),
			},
			httpMethod: http.MethodGet,
			want:       []string{"test-current-secret"},
		},
		{
			name: "deprecation policy is valid and deprecated key is defined",
			fields: fields{
				SecretProvider: &EnvironmentSecretProvider{
					CurrentSecretHeaderName:    "API_TOKEN_SECRET",
					DeprecatedSecretHeaderName: "DEPRECATED_API_TOKEN_SECRET",
				},
				DeprecationExpirationPolicy: func() DeprecationExpirationPolicy {
					p, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(time.Minute).Format(time.RFC3339))
					require.NoError(t, err)
					return p
				}(),
			},
			httpMethod: http.MethodGet,
			want:       []string{"test-current-secret", "test-deprecated-current-secret"},
		},
		{
			name: "deprecation policy is invalid and deprecated key is defined",
			fields: fields{
				SecretProvider: &EnvironmentSecretProvider{
					CurrentSecretHeaderName:    "API_TOKEN_SECRET",
					DeprecatedSecretHeaderName: "DEPRECATED_API_TOKEN_SECRET",
				},
				DeprecationExpirationPolicy: func() DeprecationExpirationPolicy {
					p, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(-time.Second).Format(time.RFC3339))
					require.NoError(t, err)
					return p
				}(),
			},
			httpMethod: http.MethodGet,
			want:       []string{"test-current-secret"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Authorizer{
				SecretProvider:              tt.fields.SecretProvider,
				DeprecationExpirationPolicy: tt.fields.DeprecationExpirationPolicy,
				ReadOnly:                    tt.fields.ReadOnly,
			}
			assert.Equalf(t, tt.want, a.availableAPIKeys(tt.httpMethod), "availableAPIKeys()")
		})
	}
}

func TestAuthorizer_AvailableHTTPMethods(t *testing.T) {
	type fields struct {
		SecretProvider              SecretProvider
		DeprecationExpirationPolicy DeprecationExpirationPolicy
		ReadOnly                    bool
		AllowedHTTPMethodsOverride  []string
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Authorizer{
				SecretProvider:              tt.fields.SecretProvider,
				DeprecationExpirationPolicy: tt.fields.DeprecationExpirationPolicy,
				ReadOnly:                    tt.fields.ReadOnly,
				AllowedHTTPMethodsOverride:  tt.fields.AllowedHTTPMethodsOverride,
			}
			assert.Equalf(t, tt.want, a.AvailableHTTPMethods(), "AvailableHTTPMethods()")
		})
	}
}

type testSecretProvider struct {
	SecretProvider
	currentSecret            string
	deprecatedSecret         string
	currentReadonlySecret    string
	deprecatedReadonlySecret string
}

func (p testSecretProvider) GetCurrentSecret() string            { return p.currentSecret }
func (p testSecretProvider) GetDeprecatedSecret() string         { return p.deprecatedSecret }
func (p testSecretProvider) GetCurrentReadonlySecret() string    { return p.currentReadonlySecret }
func (p testSecretProvider) GetDeprecatedReadonlySecret() string { return p.deprecatedReadonlySecret }

func TestAuthorizer_IsValidRequest(t *testing.T) {
	type fields struct {
		SecretProvider              SecretProvider
		DeprecationExpirationPolicy DeprecationExpirationPolicy
		ReadOnly                    bool
		AllowedHTTPMethodsOverride  []string
	}
	type args struct {
		r          *http.Request
		requestKey string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "using read-only secret with HTTP method override",
			fields: fields{
				SecretProvider:             &testSecretProvider{currentReadonlySecret: "secret-api-key"},
				ReadOnly:                   true,
				AllowedHTTPMethodsOverride: []string{http.MethodPost},
			},
			args: args{
				r: &http.Request{
					Method: http.MethodPost,
				},
				requestKey: "secret-api-key",
			},
			want: true,
		},
		{
			name: "readonly using read-write secret",
			fields: fields{
				SecretProvider: &testSecretProvider{currentSecret: "secret-api-key"},
				ReadOnly:       true,
			},
			args: args{
				r: &http.Request{
					Method: http.MethodPost,
				},
				requestKey: "secret-api-key",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Authorizer{
				SecretProvider:              tt.fields.SecretProvider,
				DeprecationExpirationPolicy: tt.fields.DeprecationExpirationPolicy,
				ReadOnly:                    tt.fields.ReadOnly,
				AllowedHTTPMethodsOverride:  tt.fields.AllowedHTTPMethodsOverride,
			}
			assert.Equalf(t, tt.want, a.IsValidRequest(tt.args.r, tt.args.requestKey), "IsValidRequest(%v, %v)", tt.args.r, tt.args.requestKey)
		})
	}
}
