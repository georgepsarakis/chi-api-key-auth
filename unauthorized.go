package apikey

import (
	"context"
	"net/http"
)

type ctxKey struct{}

var unauthorizedContextKey = ctxKey{} //nolint:gochecknoglobals

func NewUnauthorizedContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, unauthorizedContextKey, true)
}

func IsUnauthorized(ctx context.Context) bool {
	unauthorized, ok := ctx.Value(unauthorizedContextKey).(bool)
	return ok && unauthorized
}

func DefaultUnauthorizedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
