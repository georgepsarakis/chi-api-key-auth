package apikey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPITokenAuth_Allow(t *testing.T) {
	router := chi.NewRouter()
	headerName := "X_API_KEY"
	t.Setenv(headerName, "test-x-api-key-123")

	router.Use(
		Authorize(Options{
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider: &EnvironmentSecretProvider{
				CurrentSecretHeaderName: headerName,
			},
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

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t,
		"Authorization Header Provider",
		string(data))
}

func TestAPITokenAuth_Deny(t *testing.T) {
	router := chi.NewRouter()
	headerName := "X_API_KEY"
	t.Setenv(headerName, "test-x-api-key-567")

	router.Use(
		Authorize(Options{
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider: &EnvironmentSecretProvider{
				CurrentSecretHeaderName: headerName,
			},
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

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Empty(t, data)
}

func TestAPITokenAuth_Deny_Readonly_MethodNotSupported(t *testing.T) {
	router := chi.NewRouter()
	headerName := "X_API_KEY"
	secret := "test-x-api-key-567"
	t.Setenv(headerName, secret)

	router.Use(
		Authorize(Options{
			ReadOnly:           true,
			HeaderAuthProvider: AuthorizationHeader{},
			SecretProvider: &EnvironmentSecretProvider{
				ReadonlySecretHeaderName: headerName,
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
	req.Header.Set(HeaderNameAuthorization, fmt.Sprintf("Bearer %s", secret))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Empty(t, data)
}
