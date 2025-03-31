package apikey

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeprecationExpirationPolicy_Allow(t *testing.T) {
	t.Parallel()

	type args struct {
		datetime string
	}
	tests := []struct {
		name    string
		args    args
		want    assert.BoolAssertionFunc
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "timestamp in the future - allowed",
			args:    args{datetime: time.Now().Add(time.Minute).Format(time.RFC3339)},
			want:    assert.True,
			wantErr: require.NoError,
		},
		{
			name:    "timestamp in the past - not allowed",
			args:    args{datetime: time.Now().Add(-time.Second).Format(time.RFC3339)},
			want:    assert.False,
			wantErr: require.NoError,
		},
		{
			name:    "invalid timestamp",
			args:    args{datetime: "2024-01-05"},
			wantErr: require.Error,
			want:    assert.False,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewDeprecationExpirationPolicyFromString(tt.args.datetime)
			tt.wantErr(t, err, fmt.Sprintf("DeprecationExpirationPolicyFromString(%v)", tt.args.datetime))
			tt.want(t, p.Allow())
		})
	}
}

func TestDeprecationExpirationPolicyFromEnvironment(t *testing.T) {
	// Expiration set in the future
	t.Setenv("API_TOKEN_EXPIRATION_TIME", time.Now().Add(time.Minute).Format(time.RFC3339))
	{
		p, err := NewDeprecationExpirationPolicyFromEnvironment("API_TOKEN_EXPIRATION_TIME")
		require.NoError(t, err)
		require.True(t, p.Allow())
	}

	// Already expired
	t.Setenv("API_TOKEN_EXPIRATION_TIME", time.Now().Add(-time.Second).Format(time.RFC3339))

	{
		p, err := NewDeprecationExpirationPolicyFromEnvironment("API_TOKEN_EXPIRATION_TIME")
		require.NoError(t, err)
		require.False(t, p.Allow())
	}
}
