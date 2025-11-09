package apikey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envVariableName = "CONFIG_API_KEY_CURRENT"

func TestAPITokenAuth_Allow(t *testing.T) {
	router := chi.NewRouter()

	assert.NotEmpty(t, apiKeySecret(t))

	t.Setenv(envVariableName, "test-x-api-key-123")
	router.Use(
		Authorize(Options{
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider:     NewEnvironmentSecretProviderReadWrite(envVariableName, ""),
		}))
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Authorization Header Provider"))
		require.NoError(t, err)
	})
	srv := httptest.NewServer(router)
	defer srv.Close()

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set(HeaderNameAuthorization, "Bearer test-x-api-key-123")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t,
		"Authorization Header Provider",
		string(data))
}

func TestAPITokenAuth_Deny(t *testing.T) {
	router := chi.NewRouter()
	t.Setenv(envVariableName, apiKeySecret(t))

	router.Use(
		Authorize(Options{
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider:     NewEnvironmentSecretProviderReadWrite(envVariableName, ""),
		}))
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("readonly / Authorization Header Provider"))
		require.NoError(t, err)
	})
	srv := httptest.NewServer(router)
	defer srv.Close()

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set(HeaderNameAuthorization, "Bearer test-x-api-key-123")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Empty(t, data)
}

func TestAPITokenAuth_Deny_Readonly_MethodNotSupported(t *testing.T) {
	router := chi.NewRouter()
	t.Setenv(envVariableName, apiKeySecret(t))

	router.Use(
		Authorize(Options{
			ReadOnly:           true,
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider:     NewEnvironmentSecretProviderReadonly(envVariableName, ""),
		}))
	router.Post("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("readonly / Authorization Header Provider"))
		require.NoError(t, err)
	})
	srv := httptest.NewServer(router)
	defer srv.Close()

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set(HeaderNameAuthorization, fmt.Sprintf("Bearer %s", apiKeySecret(t)))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Empty(t, data)
}

func TestAPITokenAuth_Deny_CustomFailureHandler(t *testing.T) {
	router := chi.NewRouter()
	secret := apiKeySecret(t) + "-failure"

	t.Setenv(envVariableName, secret)

	router.Use(
		Authorize(Options{
			ReadOnly:           true,
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider:     NewEnvironmentSecretProviderReadonly(envVariableName, ""),
			FailureHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte("something went wrong in " + t.Name()))
				require.NoError(t, err)
			},
		}))
	router.Post("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("readonly / Authorization Header Provider"))
		require.NoError(t, err)
	})
	srv := httptest.NewServer(router)
	defer srv.Close()

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set(HeaderNameAuthorization, fmt.Sprintf("Bearer %s", apiKeySecret(t)))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, []byte("something went wrong in TestAPITokenAuth_Deny_CustomFailureHandler"), data, string(data))
}

func TestAPITokenAuth_Deny_NoSecretFoundInRequest(t *testing.T) {
	router := chi.NewRouter()

	t.Setenv(envVariableName, apiKeySecret(t))

	router.Use(
		Authorize(Options{
			ReadOnly:           true,
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider:     NewEnvironmentSecretProviderReadonly(envVariableName, ""),
			FailureHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte("something went wrong in " + t.Name()))
				require.NoError(t, err)
			},
		}))
	router.Post("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("readonly / Authorization Header Provider"))
		require.NoError(t, err)
	})
	srv := httptest.NewServer(router)
	defer srv.Close()

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, []byte("something went wrong in TestAPITokenAuth_Deny_NoSecretFoundInRequest"), data, string(data))
}

func TestNewOptions(t *testing.T) {
	t.Parallel()

	opts := NewOptions()

	assert.NotNil(t, opts.SecretProvider)
	assert.NotNil(t, opts.HeaderAuthProvider)
	assert.False(t, opts.ReadOnly)
	assert.Nil(t, opts.FailureHandler)
	// DeprecationExpirationPolicy is a struct, not a pointer, so it will be zero value
	assert.False(t, opts.DeprecationExpirationPolicy.Allow())
}

func TestNewReadonlyOptions(t *testing.T) {
	t.Parallel()

	opts := NewReadonlyOptions()

	assert.NotNil(t, opts.SecretProvider)
	assert.NotNil(t, opts.HeaderAuthProvider)
	assert.True(t, opts.ReadOnly)
	assert.Nil(t, opts.FailureHandler)
}

func TestDefaultSecretProvider(t *testing.T) {
	t.Parallel()

	provider := defaultSecretProvider()

	assert.Equal(t, "CHI_API_KEY", provider.CurrentSecretHeaderName)
	assert.Equal(t, "CHI_API_KEY_DEPRECATED", provider.DeprecatedSecretHeaderName)
	assert.Equal(t, "CHI_API_KEY_READONLY", provider.ReadonlySecretHeaderName)
	assert.Equal(t, "CHI_API_KEY_READONLY_DEPRECATED", provider.DeprecatedReadonlySecretHeaderName)
}

func apiKeySecret(t *testing.T) string {
	t.Helper()
	return "test-" + strings.Repeat("t", 20)
}
