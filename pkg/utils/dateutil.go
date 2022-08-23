package utils

import (
	"time"

	"github.com/danielpacak/kube-security-manager/pkg/ext"
)

// DurationExceeded  check if duration is now meaning zero
func DurationExceeded(duration time.Duration) bool {
	return duration.Nanoseconds() <= 0
}

// timeToExpiration  return the duration between time to expiration
func timeToExpiration(expiresAt time.Time, clock ext.Clock) time.Duration {
	return expiresAt.Sub(clock.Now())
}

// IsTTLExpired check whether current time has exceeded creation time + ttl duration
func IsTTLExpired(ttl time.Duration, creationTime time.Time, clock ext.Clock) (bool, time.Duration) {
	durationToTTLExpiration := timeToExpiration(creationTime.Add(ttl), clock)
	return DurationExceeded(durationToTTLExpiration), durationToTTLExpiration
}
