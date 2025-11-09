package apikey

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUnauthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{
			name: "context with unauthorized flag",
			ctx:  NewUnauthorizedContext(context.Background()),
			want: true,
		},
		{
			name: "context without unauthorized flag",
			ctx:  context.Background(),
			want: false,
		},
		{
			name: "context with false value",
			ctx:  context.WithValue(context.Background(), unauthorizedContextKey, false),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, IsUnauthorized(tt.ctx))
		})
	}
}
