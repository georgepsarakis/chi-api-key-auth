package apikey

import (
	"context"
	"net/http"
)

type ctxKey string

const UnauthorizedContextKey ctxKey = "unauthorized"

func NewUnauthorizedContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, UnauthorizedContextKey, true)
}

func IsUnauthorized(ctx context.Context) bool {
	unauthorized, ok := ctx.Value(UnauthorizedContextKey).(bool)
	return ok && unauthorized
}

func DefaultUnauthorizedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
