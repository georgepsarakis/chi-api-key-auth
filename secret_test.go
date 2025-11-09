package apikey

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXApiKeyHeader_Name(t *testing.T) {
	header := XApiKeyHeader{}
	assert.Equal(t, HeaderNameXApiKey, header.Name())
}

func TestXApiKeyHeader_Secret(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantSecret  string
		wantOk      bool
	}{
		{
			name:        "valid key with spaces",
			headerValue: "  test-key-123  ",
			wantSecret:  "test-key-123",
			wantOk:      true,
		},
		{
			name:        "valid key without spaces",
			headerValue: "test-key-123",
			wantSecret:  "test-key-123",
			wantOk:      true,
		},
		{
			name:        "empty header",
			headerValue: "",
			wantSecret:  "",
			wantOk:      false,
		},
		{
			name:        "only spaces",
			headerValue: "   ",
			wantSecret:  "",
			wantOk:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			header := XApiKeyHeader{}
			h := http.Header{}
			h.Set(header.Name(), tt.headerValue)
			req := &http.Request{Header: h}

			secret, ok := header.Secret(req)
			assert.Equal(t, tt.wantSecret, secret)
			assert.Equal(t, tt.wantOk, ok)
		})
	}
}

func TestEnvironmentSecretProvider_GetCurrentReadonlySecret(t *testing.T) {
	const envKey = "READONLY_SECRET"
	const envValue = "readonly-key-value"

	t.Setenv(envKey, envValue)

	provider := NewEnvironmentSecretProviderReadonly(envKey, "")

	secret := provider.GetCurrentReadonlySecret()
	assert.Equal(t, envValue, secret)
}

func TestEnvironmentSecretProvider_GetCurrentSecret(t *testing.T) {
	envKey := "CACHE_TEST_KEY"
	envValue := "cached-value"
	t.Setenv(envKey, envValue)

	provider := NewEnvironmentSecretProviderReadWrite(envKey, "")

	// First call should load from environment
	first := provider.GetCurrentSecret()
	assert.Equal(t, envValue, first)

	// Change environment variable
	t.Setenv(envKey, "new-value")

	// Second call should return cached value
	second := provider.GetCurrentSecret()
	assert.Equal(t, envValue, second, "Should return cached value, not new environment value")
}

func TestEnvironmentSecretProvider_GetDeprecatedReadonlySecret(t *testing.T) {
	t.Setenv("DEPRECATED_READONLY_SECRET", "deprecated-readonly-value")

	provider := NewEnvironmentSecretProviderReadonly("", "DEPRECATED_READONLY_SECRET")

	secret := provider.GetDeprecatedReadonlySecret()
	assert.Equal(t, "deprecated-readonly-value", secret)
}
