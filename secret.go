package apikey

import (
	"net/http"
	"os"
	"strings"
	"sync"
)

type SecretProvider interface {
	GetCurrentSecret() string
	GetDeprecatedSecret() string
	GetCurrentReadonlySecret() string
	GetDeprecatedReadonlySecret() string
}

type EnvironmentSecretProvider struct {
	SecretProvider
	CurrentSecretHeaderName            string
	DeprecatedSecretHeaderName         string
	ReadonlySecretHeaderName           string
	DeprecatedReadonlySecretHeaderName string
	cache                              sync.Map
}

func (p *EnvironmentSecretProvider) GetCurrentSecret() string {
	return p.load(p.CurrentSecretHeaderName)
}

func (p *EnvironmentSecretProvider) load(key string) string {
	if v, ok := p.cache.Load(key); ok {
		return v.(string)
	}
	v := os.Getenv(key)
	p.cache.Store(key, v)
	return v
}

func (p *EnvironmentSecretProvider) GetDeprecatedSecret() string {
	return p.load(p.DeprecatedSecretHeaderName)
}

func (p *EnvironmentSecretProvider) GetCurrentReadonlySecret() string {
	return p.load(p.ReadonlySecretHeaderName)
}

type HeaderAuthProvider interface {
	Name() string
	Secret(r *http.Request) (string, bool)
}

type XApiKeyHeader struct {
	HeaderAuthProvider
}

var _ HeaderAuthProvider = (*XApiKeyHeader)(nil)

const HeaderNameXApiKey = "X-Api-Key" // #nosec G101

func (h XApiKeyHeader) Name() string {
	return HeaderNameXApiKey
}

func (h XApiKeyHeader) Secret(r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get(h.Name()))
	return key, key != ""
}

type AuthorizationHeader struct {
	HeaderAuthProvider
}

const HeaderNameAuthorization = "Authorization"
const bearerPrefix = "Bearer "

func (h AuthorizationHeader) Name() string {
	return HeaderNameAuthorization
}

func (h AuthorizationHeader) Secret(r *http.Request) (string, bool) {
	secret := r.Header.Get(h.Name())
	if !strings.HasPrefix(secret, bearerPrefix) {
		return "", false
	}
	secret = strings.TrimSpace(strings.TrimPrefix(secret, bearerPrefix))
	return secret, secret != ""
}
