package utils

import (
	"testing"
	"time"

	"github.com/danielpacak/kube-security-manager/pkg/ext"
	"github.com/stretchr/testify/assert"
)

func TestDurationExceeded(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     bool
	}{
		{name: "duration future", duration: time.Duration(100), want: false},
		{name: "duration now", duration: time.Duration(0), want: true},
		{name: "duration pass", duration: time.Duration(-2), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceeded := DurationExceeded(tt.duration)
			assert.Equal(t, exceeded, tt.want)
		})
	}
}

func TestTTLIsNotExpired(t *testing.T) {
	ttlReportAnnotationStr := "10h"
	ttlReportTime, _ := time.ParseDuration(ttlReportAnnotationStr)
	creationTime := time.Now()
	ttlExpired, duration := IsTTLExpired(ttlReportTime, creationTime, ext.NewSystemClock())
	assert.True(t, duration > 0)
	assert.False(t, ttlExpired)
}

func TestTTLIsExpired(t *testing.T) {
	ttlReportAnnotationStr := "10s"
	ttlReportTime, _ := time.ParseDuration(ttlReportAnnotationStr)
	creationTime := time.Now()
	then := creationTime.Add(time.Duration(-10) * time.Minute)
	ttlExpired, duration := IsTTLExpired(ttlReportTime, then, ext.NewSystemClock())
	assert.True(t, duration <= 0)
	assert.True(t, ttlExpired)
}
