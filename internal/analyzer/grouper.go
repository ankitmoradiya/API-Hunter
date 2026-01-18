// apihunter/internal/analyzer/grouper.go
package analyzer

import (
	"sort"
	"strings"

	"github.com/apihunter/apihunter/internal/models"
)

// EndpointGroup represents a group of related endpoints
type EndpointGroup struct {
	Name      string
	Endpoints []models.Endpoint
}

// Grouper organizes endpoints by resource
type Grouper struct{}

// NewGrouper creates a new grouper
func NewGrouper() *Grouper {
	return &Grouper{}
}

// GroupEndpoints organizes endpoints by resource
func (g *Grouper) GroupEndpoints(endpoints []models.Endpoint) []EndpointGroup {
	groups := make(map[string][]models.Endpoint)

	for _, ep := range endpoints {
		groupName := g.extractGroupName(ep.NormalizedPath)
		groups[groupName] = append(groups[groupName], ep)
	}

	var result []EndpointGroup
	for name, eps := range groups {
		// Sort endpoints within group
		sort.Slice(eps, func(i, j int) bool {
			return eps[i].NormalizedPath < eps[j].NormalizedPath
		})
		result = append(result, EndpointGroup{Name: name, Endpoints: eps})
	}

	// Sort groups alphabetically
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

func (g *Grouper) extractGroupName(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")

	// Skip common prefixes
	skipPrefixes := []string{"api", "v1", "v2", "v3", "rest"}
	startIdx := 0
	for i, part := range parts {
		isPrefix := false
		for _, prefix := range skipPrefixes {
			if strings.EqualFold(part, prefix) || strings.HasPrefix(strings.ToLower(part), "v") {
				isPrefix = true
				break
			}
		}
		if !isPrefix {
			startIdx = i
			break
		}
	}

	if startIdx < len(parts) {
		name := parts[startIdx]
		// Remove parameter placeholders
		if !strings.HasPrefix(name, "{") {
			return strings.Title(strings.TrimSuffix(name, "s")) + "s"
		}
	}

	return "Other"
}
