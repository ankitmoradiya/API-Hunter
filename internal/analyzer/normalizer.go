// apihunter/internal/analyzer/normalizer.go
package analyzer

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/apihunter/apihunter/internal/models"
)

var paramPatterns = []struct {
	pattern *regexp.Regexp
	name    string
	ptype   string
}{
	{regexp.MustCompile(`/\d+(/|$)`), "id", "integer"},
	{regexp.MustCompile(`/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(/|$)`), "uuid", "string"},
	{regexp.MustCompile(`/[a-f0-9]{24}(/|$)`), "objectId", "string"},
	{regexp.MustCompile(`/\d{4}-\d{2}-\d{2}(/|$)`), "date", "string"},
	{regexp.MustCompile(`/(usr|user|org|team|proj)_[a-zA-Z0-9]+(/|$)`), "prefixedId", "string"},
}

// Normalizer handles URL normalization and path parameter detection
type Normalizer struct{}

// NewNormalizer creates a new normalizer
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize processes endpoints and detects path parameters
func (n *Normalizer) Normalize(endpoints []models.Endpoint) []models.Endpoint {
	normalized := make(map[string]*models.Endpoint)

	for _, ep := range endpoints {
		parsed, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}

		path := parsed.Path
		normalizedPath, params := n.normalizePath(path)

		key := parsed.Host + normalizedPath

		if existing, ok := normalized[key]; ok {
			// Merge query params
			existing.QueryParams = n.mergeParams(existing.QueryParams, n.extractQueryParams(parsed))
		} else {
			newEp := models.Endpoint{
				URL:            ep.URL,
				Path:           path,
				NormalizedPath: normalizedPath,
				Parameters:     params,
				QueryParams:    n.extractQueryParams(parsed),
				Source:         ep.Source,
				DiscoveredAt:   ep.DiscoveredAt,
			}
			normalized[key] = &newEp
		}
	}

	result := make([]models.Endpoint, 0, len(normalized))
	for _, ep := range normalized {
		result = append(result, *ep)
	}
	return result
}

func (n *Normalizer) normalizePath(path string) (string, []models.Parameter) {
	var params []models.Parameter
	normalizedPath := path

	for _, pp := range paramPatterns {
		if pp.pattern.MatchString(path) {
			paramName := pp.name
			// Try to infer better name from path context
			parts := strings.Split(path, "/")
			for i, part := range parts {
				if pp.pattern.MatchString("/" + part + "/") && i > 0 {
					resource := strings.TrimSuffix(parts[i-1], "s")
					paramName = resource + "Id"
					break
				}
			}

			normalizedPath = pp.pattern.ReplaceAllString(normalizedPath, "/{"+paramName+"}/")
			normalizedPath = strings.TrimSuffix(normalizedPath, "/")

			params = append(params, models.Parameter{
				Name:     paramName,
				Type:     pp.ptype,
				In:       "path",
				Required: true,
			})
		}
	}

	return normalizedPath, params
}

func (n *Normalizer) extractQueryParams(u *url.URL) []models.Parameter {
	var params []models.Parameter
	for key, values := range u.Query() {
		param := models.Parameter{
			Name:     key,
			Type:     "string",
			In:       "query",
			Required: false,
		}
		if len(values) > 0 {
			param.Example = values[0]
		}
		params = append(params, param)
	}
	return params
}

func (n *Normalizer) mergeParams(existing, new []models.Parameter) []models.Parameter {
	seen := make(map[string]bool)
	for _, p := range existing {
		seen[p.Name] = true
	}
	for _, p := range new {
		if !seen[p.Name] {
			existing = append(existing, p)
			seen[p.Name] = true
		}
	}
	return existing
}
