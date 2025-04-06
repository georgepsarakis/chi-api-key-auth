package apikey

import (
	"net/http"
)

type Options struct {
	ReadOnly                    bool
	FailureHandler              http.HandlerFunc
	SecretProvider              SecretProvider
	DeprecationExpirationPolicy DeprecationExpirationPolicy
	HeaderAuthProvider          HeaderAuthProvider
	// AllowedHTTPMethodsOverride allows customization of accepted HTTP methods.
	// A common use case is POST requests that actually perform read operations.
	AllowedHTTPMethodsOverride []string
}

var defaultSecretProvider = func() *EnvironmentSecretProvider {
	return &EnvironmentSecretProvider{
		CurrentSecretHeaderName:            "CHI_API_KEY",
		DeprecatedSecretHeaderName:         "CHI_API_KEY_DEPRECATED",
		ReadonlySecretHeaderName:           "CHI_API_KEY_READONLY",
		DeprecatedReadonlySecretHeaderName: "CHI_API_KEY_READONLY_DEPRECATED",
	}
}

func NewOptions() Options {
	return Options{
		SecretProvider:     defaultSecretProvider(),
		HeaderAuthProvider: AuthorizationHeader{},
	}
}

func NewReadonlyOptions() Options {
	return Options{
		SecretProvider:     defaultSecretProvider(),
		ReadOnly:           true,
		HeaderAuthProvider: AuthorizationHeader{},
	}
}

// Authorize implements a simple middleware handler for creating header-based authentication schemes.
func Authorize(options Options) func(next http.Handler) http.Handler {
	if options.FailureHandler == nil {
		options.FailureHandler = DefaultUnauthorizedHandler()
	}
	scope := PermissionScopeReadWrite
	if options.ReadOnly {
		scope = PermissionScopeReadonly
	}
	auth := NewAuthorizer(
		options.SecretProvider,
		options.DeprecationExpirationPolicy,
		scope,
		options.AllowedHTTPMethodsOverride,
	)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestKey, ok := options.HeaderAuthProvider.Secret(r)
			if !ok {
				options.FailureHandler(w, r)
				return
			}
			if !auth.IsValidRequest(r, requestKey) {
				r = r.WithContext(NewUnauthorizedContext(r.Context()))
				options.FailureHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
