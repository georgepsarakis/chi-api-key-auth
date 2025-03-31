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

func NewOptions() Options {
	return Options{
		SecretProvider: &EnvironmentSecretProvider{
			CurrentSecretHeaderName:            "CHI_API_KEY",
			DeprecatedSecretHeaderName:         "CHI_API_KEY_DEPRECATED",
			ReadonlySecretHeaderName:           "CHI_API_KEY_READONLY",
			DeprecatedReadonlySecretHeaderName: "CHI_API_KEY_READONLY_DEPRECATED",
		},
		HeaderAuthProvider: AuthorizationHeader{},
	}
}

var readonlyHTTPMethods = []string{http.MethodHead, http.MethodGet}
var allHTTPMethods = []string{
	http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodGet}

// Authorize implements a simple middleware handler for creating header-based authentication schemes.
func Authorize(options Options) func(next http.Handler) http.Handler {
	if options.FailureHandler == nil {
		options.FailureHandler = DefaultUnauthorizedHandler()
	}
	auth := Authorizer{
		SecretProvider:              options.SecretProvider,
		DeprecationExpirationPolicy: options.DeprecationExpirationPolicy,
		AllowedHTTPMethodsOverride:  options.AllowedHTTPMethodsOverride,
	}
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
