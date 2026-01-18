// apihunter/internal/analyzer/inferrer.go
package analyzer

import (
	"regexp"
	"strings"

	"github.com/apihunter/apihunter/internal/models"
)

// Inferrer infers HTTP methods from URL patterns
type Inferrer struct{}

// NewInferrer creates a new inferrer
func NewInferrer() *Inferrer {
	return &Inferrer{}
}

var methodPatterns = []struct {
	pattern *regexp.Regexp
	methods []string
}{
	{regexp.MustCompile(`/login|/signin|/authenticate`), []string{"POST"}},
	{regexp.MustCompile(`/logout|/signout`), []string{"POST"}},
	{regexp.MustCompile(`/register|/signup`), []string{"POST"}},
	{regexp.MustCompile(`/upload`), []string{"POST"}},
	{regexp.MustCompile(`/download`), []string{"GET"}},
	{regexp.MustCompile(`/export`), []string{"GET", "POST"}},
	{regexp.MustCompile(`/import`), []string{"POST"}},
	{regexp.MustCompile(`/search`), []string{"GET", "POST"}},
	{regexp.MustCompile(`/delete`), []string{"POST", "DELETE"}},
	{regexp.MustCompile(`/create`), []string{"POST"}},
	{regexp.MustCompile(`/update`), []string{"POST", "PUT", "PATCH"}},
	{regexp.MustCompile(`/activate|/enable`), []string{"POST"}},
	{regexp.MustCompile(`/deactivate|/disable`), []string{"POST"}},
	{regexp.MustCompile(`/verify|/confirm`), []string{"POST", "GET"}},
	{regexp.MustCompile(`/reset`), []string{"POST"}},
	{regexp.MustCompile(`/callback|/webhook`), []string{"POST"}},
}

// InferMethods adds inferred HTTP methods to endpoints
func (i *Inferrer) InferMethods(endpoints []models.Endpoint) []models.Endpoint {
	for idx := range endpoints {
		ep := &endpoints[idx]
		if len(ep.Methods) == 0 {
			ep.Methods = i.inferMethodsForPath(ep.NormalizedPath)
		}
	}
	return endpoints
}

func (i *Inferrer) inferMethodsForPath(path string) []string {
	lowerPath := strings.ToLower(path)

	// Check specific patterns first
	for _, mp := range methodPatterns {
		if mp.pattern.MatchString(lowerPath) {
			return mp.methods
		}
	}

	// Check if path ends with an ID parameter (resource/{id})
	if strings.HasSuffix(path, "Id}") || strings.HasSuffix(path, "id}") {
		return []string{"GET", "PUT", "PATCH", "DELETE"}
	}

	// Default: collection endpoint
	return []string{"GET", "POST"}
}
