package apikey

import (
	"crypto/subtle"
	"net/http"
	"slices"
)

type Authorizer struct {
	SecretProvider              SecretProvider
	DeprecationExpirationPolicy DeprecationExpirationPolicy
	ReadOnly                    bool
	AllowedHTTPMethodsOverride  []string
}

func (a Authorizer) AvailableHTTPMethods() []string {
	if len(a.AllowedHTTPMethodsOverride) > 0 {
		return a.AllowedHTTPMethodsOverride
	}
	if a.ReadOnly {
		return []string{http.MethodHead, http.MethodGet}
	}
	return []string{
		http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodGet,
	}
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
	if a.ReadOnly && slices.Contains(a.AvailableHTTPMethods(), httpMethod) {
		if secret := a.SecretProvider.GetCurrentReadonlySecret(); secret != "" {
			keys = append(keys, secret)
		}
	}
	if !a.DeprecationExpirationPolicy.Allow() {
		return keys
	}

	if a.ReadOnly {
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
