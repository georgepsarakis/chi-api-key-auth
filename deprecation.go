package apikey

import (
	"os"
	"time"
)

type DeprecationExpirationPolicy struct {
	expireAt time.Time
}

func (p DeprecationExpirationPolicy) Allow() bool {
	return time.Now().Before(p.expireAt)
}

func NewDeprecationExpirationPolicyFromEnvironment(variableName string) (DeprecationExpirationPolicy, error) {
	p, err := NewDeprecationExpirationPolicyFromString(os.Getenv(variableName))
	if err != nil {
		return DeprecationExpirationPolicy{}, err
	}
	return p, nil
}

func NewDeprecationExpirationPolicyFromString(datetime string) (DeprecationExpirationPolicy, error) {
	expirationTime, err := time.Parse(time.RFC3339, datetime)
	if err != nil {
		return DeprecationExpirationPolicy{}, err
	}
	return DeprecationExpirationPolicy{
		expireAt: expirationTime,
	}, nil
}
