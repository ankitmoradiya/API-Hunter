// apihunter/internal/analyzer/tagger.go
package analyzer

import (
	"regexp"
	"strings"

	"github.com/apihunter/apihunter/internal/models"
)

// Tagger assigns risk levels and tags to endpoints
type Tagger struct{}

// NewTagger creates a new tagger
func NewTagger() *Tagger {
	return &Tagger{}
}

var riskPatterns = []struct {
	pattern *regexp.Regexp
	risk    models.RiskLevel
	tags    []string
}{
	// Critical
	{regexp.MustCompile(`/auth|/login|/signin|/oauth`), models.RiskCritical, []string{"auth"}},
	{regexp.MustCompile(`/admin`), models.RiskCritical, []string{"admin"}},
	{regexp.MustCompile(`/upload|/import`), models.RiskCritical, []string{"file-upload"}},
	{regexp.MustCompile(`/password|/passwd|/pwd`), models.RiskCritical, []string{"password"}},
	{regexp.MustCompile(`/token|/jwt|/refresh`), models.RiskCritical, []string{"token"}},
	{regexp.MustCompile(`/payment|/checkout|/billing`), models.RiskCritical, []string{"payment"}},
	{regexp.MustCompile(`/\.env|/config\.|/debug`), models.RiskCritical, []string{"sensitive-file"}},
	{regexp.MustCompile(`/graphql`), models.RiskCritical, []string{"graphql"}},

	// High
	{regexp.MustCompile(`/user|/profile|/account`), models.RiskHigh, []string{"pii"}},
	{regexp.MustCompile(`/export|/download`), models.RiskHigh, []string{"data-export"}},
	{regexp.MustCompile(`/api[_-]?key|/secret|/credential`), models.RiskHigh, []string{"secrets"}},
	{regexp.MustCompile(`/config|/setting`), models.RiskHigh, []string{"config"}},
	{regexp.MustCompile(`/internal|/private`), models.RiskHigh, []string{"internal"}},

	// Medium
	{regexp.MustCompile(`/search|/query|/filter`), models.RiskMedium, []string{"injection-point"}},
	{regexp.MustCompile(`/list|/all`), models.RiskMedium, []string{"enumeration"}},
	{regexp.MustCompile(`\?.*=`), models.RiskMedium, []string{"params"}},
}

// TagEndpoints assigns risk and tags to endpoints
func (t *Tagger) TagEndpoints(endpoints []models.Endpoint) []models.Endpoint {
	for idx := range endpoints {
		ep := &endpoints[idx]
		t.tagEndpoint(ep)
	}
	return endpoints
}

func (t *Tagger) tagEndpoint(ep *models.Endpoint) {
	pathToCheck := strings.ToLower(ep.NormalizedPath + ep.URL)

	highestRisk := models.RiskLow
	var allTags []string

	for _, rp := range riskPatterns {
		if rp.pattern.MatchString(pathToCheck) {
			if riskPriority(rp.risk) > riskPriority(highestRisk) {
				highestRisk = rp.risk
			}
			allTags = append(allTags, rp.tags...)
		}
	}

	ep.Risk = highestRisk
	ep.Tags = uniqueTags(allTags)
}

func riskPriority(r models.RiskLevel) int {
	switch r {
	case models.RiskCritical:
		return 4
	case models.RiskHigh:
		return 3
	case models.RiskMedium:
		return 2
	case models.RiskLow:
		return 1
	default:
		return 0
	}
}

func uniqueTags(tags []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}
