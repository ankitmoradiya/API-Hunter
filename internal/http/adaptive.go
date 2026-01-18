// apihunter/internal/http/adaptive.go
package http

import (
	"sync"
	"time"
)

// AdaptiveRateLimiter adjusts rate based on response codes
type AdaptiveRateLimiter struct {
	baseRate       int
	currentRate    int
	minRate        int
	maxBackoff     time.Duration
	backoffMu      sync.Mutex
	consecutive429 int
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(baseRate int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseRate:    baseRate,
		currentRate: baseRate,
		minRate:     1,
		maxBackoff:  30 * time.Second,
	}
}

// OnResponse adjusts rate based on response status code
func (a *AdaptiveRateLimiter) OnResponse(statusCode int) time.Duration {
	a.backoffMu.Lock()
	defer a.backoffMu.Unlock()

	switch statusCode {
	case 429: // Too Many Requests
		a.consecutive429++
		backoff := time.Duration(1<<a.consecutive429) * time.Second
		if backoff > a.maxBackoff {
			backoff = a.maxBackoff
		}
		a.currentRate = maxInt(a.currentRate/2, a.minRate)
		return backoff

	case 403: // Forbidden - might be WAF
		a.currentRate = maxInt(a.currentRate/2, a.minRate)
		return time.Second

	case 503: // Service Unavailable
		return 2 * time.Second

	default:
		// Success - slowly recover rate
		a.consecutive429 = 0
		if a.currentRate < a.baseRate {
			a.currentRate = minInt(a.currentRate+1, a.baseRate)
		}
		return 0
	}
}

// CurrentRate returns the current rate limit
func (a *AdaptiveRateLimiter) CurrentRate() int {
	a.backoffMu.Lock()
	defer a.backoffMu.Unlock()
	return a.currentRate
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
