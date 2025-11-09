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
				SecretProvider: NewEnvironmentSecretProviderReadWrite("API_TOKEN_SECRET", ""),
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
				SecretProvider: NewEnvironmentSecretProviderReadWrite("API_TOKEN_SECRET", "DEPRECATED_API_TOKEN_SECRET"),
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
				SecretProvider: NewEnvironmentSecretProviderReadWrite("API_TOKEN_SECRET", "DEPRECATED_API_TOKEN_SECRET"),
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
				readOnly:                    tt.fields.ReadOnly,
			}
			assert.Equalf(t, tt.want, a.availableAPIKeys(tt.httpMethod), "availableAPIKeys()")
		})
	}
}

func TestAuthorizer_allowedHTTPMethods(t *testing.T) {
	type fields struct {
		SecretProvider              SecretProvider
		DeprecationExpirationPolicy DeprecationExpirationPolicy
		Scope                       PermissionScope
		AllowedHTTPMethodsOverride  []string
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "read-write",
			fields: fields{
				Scope: PermissionScopeReadWrite,
			},
			want: []string{
				http.MethodHead, http.MethodGet, http.MethodPost,
				http.MethodPatch, http.MethodDelete, http.MethodPut,
				http.MethodOptions, http.MethodConnect, http.MethodTrace,
			},
		},
		{
			name: "readonly without override",
			fields: fields{
				Scope: PermissionScopeReadonly,
			},
			want: []string{http.MethodHead, http.MethodGet, http.MethodOptions},
		},
		{
			name: "readonly with override",
			fields: fields{
				Scope:                      PermissionScopeReadonly,
				AllowedHTTPMethodsOverride: []string{http.MethodGet, http.MethodPost},
			},
			want: []string{http.MethodGet, http.MethodPost},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAuthorizer(
				tt.fields.SecretProvider,
				tt.fields.DeprecationExpirationPolicy,
				tt.fields.Scope,
				tt.fields.AllowedHTTPMethodsOverride,
			)
			assert.ElementsMatch(t, tt.want, a.allowedHTTPMethods())
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
	nonExpiredPolicy, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, err)

	expiredPolicy, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(-time.Minute).Format(time.RFC3339))
	require.NoError(t, err)

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
			name: "read-only secret with HTTP method override",
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
		{
			name: "deprecation policy fallback - non-expired",
			fields: fields{
				SecretProvider: &testSecretProvider{
					currentSecret:    "secret-api-key",
					deprecatedSecret: "deprecated-secret",
				},
				DeprecationExpirationPolicy: nonExpiredPolicy,
			},
			args: args{
				r: &http.Request{
					Method: http.MethodPost,
				},
				requestKey: "deprecated-secret",
			},
			want: true,
		},
		{
			name: "deprecation policy fallback - expired",
			fields: fields{
				SecretProvider: &testSecretProvider{
					currentSecret:    "secret-api-key",
					deprecatedSecret: "deprecated-secret",
				},
				DeprecationExpirationPolicy: expiredPolicy,
			},
			args: args{
				r: &http.Request{
					Method: http.MethodPost,
				},
				requestKey: "deprecated-secret",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := PermissionScopeReadWrite
			if tt.fields.ReadOnly {
				scope = PermissionScopeReadonly
			}
			a := NewAuthorizer(
				tt.fields.SecretProvider,
				tt.fields.DeprecationExpirationPolicy,
				scope,
				tt.fields.AllowedHTTPMethodsOverride,
			)
			assert.Equalf(t, tt.want, a.IsValidRequest(tt.args.r, tt.args.requestKey), "IsValidRequest(%v, %v)", tt.args.r, tt.args.requestKey)
		})
	}
}

func TestNewReadonlyAuthorizer(t *testing.T) {
	provider := &testSecretProvider{currentSecret: "test-secret"}
	httpMethods := []string{http.MethodGet, http.MethodPost}

	auth := NewReadonlyAuthorizer(provider, httpMethods)

	assert.Equal(t, provider, auth.SecretProvider)
	assert.True(t, auth.readOnly)
	assert.Equal(t, httpMethods, auth.allowedHTTPMethods())
}

func TestAuthorizer_IsValidRequest_EmptyRequestKey(t *testing.T) {
	provider := &testSecretProvider{
		currentSecret: "valid-key",
	}
	auth := NewAuthorizer(provider, DeprecationExpirationPolicy{}, PermissionScopeReadWrite, nil)

	req := &http.Request{Method: http.MethodGet}
	result := auth.IsValidRequest(req, "")

	assert.False(t, result, "Should return false when requestKey is empty")
}

func TestAuthorizer_IsValidRequest_EmptyKeyInLoop(t *testing.T) {
	provider := &testSecretProvider{
		currentSecret: "", // Empty secret
	}
	auth := NewAuthorizer(provider, DeprecationExpirationPolicy{}, PermissionScopeReadWrite, nil)

	req := &http.Request{Method: http.MethodGet}
	result := auth.IsValidRequest(req, "some-key")

	assert.False(t, result, "Should return false when all keys are empty")
}

func TestAuthorizer_IsValidRequest_NoMatch(t *testing.T) {
	provider := &testSecretProvider{
		currentSecret: "valid-key",
	}
	auth := NewAuthorizer(provider, DeprecationExpirationPolicy{}, PermissionScopeReadWrite, nil)

	req := &http.Request{Method: http.MethodGet}
	result := auth.IsValidRequest(req, "wrong-key")

	assert.False(t, result, "Should return false when key doesn't match")
}

func TestAuthorizer_IsValidRequest_MultipleKeys_SecondMatches(t *testing.T) {
	nonExpiredPolicy, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, err)

	provider := &testSecretProvider{
		currentSecret:    "first-key",
		deprecatedSecret: "second-key",
	}
	auth := NewAuthorizer(provider, nonExpiredPolicy, PermissionScopeReadWrite, nil)

	req := &http.Request{Method: http.MethodGet}
	result := auth.IsValidRequest(req, "second-key")

	assert.True(t, result, "Should return true when second key in list matches")
}

func TestAuthorizer_IsValidRequest_EmptyAvailableKeys(t *testing.T) {
	provider := &testSecretProvider{
		currentSecret:    "",
		deprecatedSecret: "",
	}
	auth := NewAuthorizer(provider, DeprecationExpirationPolicy{}, PermissionScopeReadWrite, nil)

	req := &http.Request{Method: http.MethodGet}
	result := auth.IsValidRequest(req, "some-key")

	assert.False(t, result, "Should return false when availableAPIKeys returns empty slice")
}

func TestAuthorizer_AvailableAPIKeys_ReadonlySecret(t *testing.T) {
	t.Setenv("READONLY_SECRET", "readonly-key")
	t.Setenv("DEPRECATED_READONLY_SECRET", "deprecated-readonly-key")

	nonExpiredPolicy, err := NewDeprecationExpirationPolicyFromString(time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, err)

	provider := NewEnvironmentSecretProvider("CURRENT_SECRET", "", "READONLY_SECRET", "DEPRECATED_READONLY_SECRET")

	auth := Authorizer{
		SecretProvider:              provider,
		DeprecationExpirationPolicy: nonExpiredPolicy,
		readOnly:                    true,
		availableHTTPMethods:        []string{http.MethodGet},
	}

	keys := auth.availableAPIKeys(http.MethodGet)
	assert.Contains(t, keys, "readonly-key", "Should include readonly secret for allowed method")
	assert.Contains(t, keys, "deprecated-readonly-key", "Should include deprecated readonly secret when policy allows")
}

func TestAuthorizer_AvailableAPIKeys_ReadonlySecret_MethodNotAllowed(t *testing.T) {
	t.Setenv("READONLY_SECRET", "readonly-key")

	provider := NewEnvironmentSecretProvider("CURRENT_SECRET", "", "READONLY_SECRET", "")

	auth := Authorizer{
		SecretProvider:       provider,
		readOnly:             true,
		availableHTTPMethods: []string{http.MethodGet}, // POST not in allowed methods
	}

	keys := auth.availableAPIKeys(http.MethodPost)
	assert.NotContains(t, keys, "readonly-key", "Should not include readonly secret for disallowed method")
}
