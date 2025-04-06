package apikey

import (
	"crypto/subtle"
	"net/http"
	"slices"
)

type PermissionScope string

const PermissionScopeReadonly = PermissionScope("readonly")
const PermissionScopeReadWrite = PermissionScope("readwrite")

type Authorizer struct {
	SecretProvider              SecretProvider
	DeprecationExpirationPolicy DeprecationExpirationPolicy
	readOnly                    bool
	allowedHTTPMethodsOverride  []string
	availableHTTPMethods        []string
}

func NewAuthorizer(secretProvider SecretProvider, deprecationPolicy DeprecationExpirationPolicy, scope PermissionScope, httpMethodsOverride []string) Authorizer {
	readonly := scope == PermissionScopeReadonly
	a := Authorizer{
		SecretProvider:              secretProvider,
		DeprecationExpirationPolicy: deprecationPolicy,
		allowedHTTPMethodsOverride:  httpMethodsOverride,
		readOnly:                    readonly,
	}
	a.availableHTTPMethods = a.allowedHTTPMethods()
	return a
}

func (a Authorizer) allowedHTTPMethods() []string {
	if a.readOnly {
		if len(a.allowedHTTPMethodsOverride) > 0 {
			return a.allowedHTTPMethodsOverride
		}
		return []string{http.MethodHead, http.MethodGet, http.MethodOptions}
	}
	return []string{
		http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodGet,
		http.MethodOptions, http.MethodConnect, http.MethodTrace,
	}
}

func NewReadonlyAuthorizer(provider SecretProvider, httpMethods []string) Authorizer {
	return NewAuthorizer(provider, DeprecationExpirationPolicy{}, PermissionScopeReadonly, httpMethods)
}

func (a Authorizer) IsValidRequest(r *http.Request, requestKey string) bool {
	if requestKey == "" {
		return false
	}
	for _, apiKey := range a.availableAPIKeys(r.Method) {
		if apiKey == "" {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(requestKey)) == 1 {
			return true
		}
	}
	return false
}

func (a Authorizer) availableAPIKeys(httpMethod string) []string {
	var keys []string
	if secret := a.SecretProvider.GetCurrentSecret(); secret != "" {
		keys = append(keys, secret)
	}
	if a.readOnly && slices.Contains(a.availableHTTPMethods, httpMethod) {
		if secret := a.SecretProvider.GetCurrentReadonlySecret(); secret != "" {
			keys = append(keys, secret)
		}
	}
	if !a.DeprecationExpirationPolicy.Allow() {
		return keys
	}

	if a.readOnly {
		if secret := a.SecretProvider.GetDeprecatedReadonlySecret(); secret != "" {
			keys = append(keys, secret)
		}
		return keys
	}
	if secret := a.SecretProvider.GetDeprecatedSecret(); secret != "" {
		keys = append(keys, secret)
	}
	return keys
}
