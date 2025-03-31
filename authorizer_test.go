package apikey

import (
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
		name   string
		fields fields
		want   []string
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
			want: []string{"test-current-secret"},
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
			want: []string{"test-current-secret", "test-deprecated-current-secret"},
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
			want: []string{"test-current-secret"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Authorizer{
				SecretProvider:              tt.fields.SecretProvider,
				DeprecationExpirationPolicy: tt.fields.DeprecationExpirationPolicy,
				ReadOnly:                    tt.fields.ReadOnly,
			}
			assert.Equalf(t, tt.want, a.AvailableAPIKeys(), "AvailableAPIKeys()")
		})
	}
}
