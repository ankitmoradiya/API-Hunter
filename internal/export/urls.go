// apihunter/internal/export/urls.go
package export

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/apihunter/apihunter/internal/models"
)

// URLExporter generates URL list files
type URLExporter struct{}

// NewURLExporter creates a new URL exporter
func NewURLExporter() *URLExporter {
	return &URLExporter{}
}

// Export generates categorized URL list files
func (e *URLExporter) Export(result *models.ScanResult, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	var allURLs, criticalURLs, highURLs, apiURLs, jsURLs []string

	for _, ep := range result.Endpoints {
		allURLs = append(allURLs, ep.URL)

		switch ep.Risk {
		case models.RiskCritical:
			criticalURLs = append(criticalURLs, ep.URL)
		case models.RiskHigh:
			highURLs = append(highURLs, ep.URL)
		}

		if isAPIURL(ep.URL) {
			apiURLs = append(apiURLs, ep.URL)
		}
	}

	for _, js := range result.JSFiles {
		jsURLs = append(jsURLs, js)
	}

	files := map[string][]string{
		"urls_all.txt":      allURLs,
		"urls_critical.txt": criticalURLs,
		"urls_high.txt":     highURLs,
		"urls_api.txt":      apiURLs,
		"urls_js.txt":       jsURLs,
	}

	for filename, urls := range files {
		if len(urls) > 0 {
			content := strings.Join(urls, "\n")
			if err := os.WriteFile(filepath.Join(outputDir, filename), []byte(content), 0644); err != nil {
				return err
			}
		}
	}

	return nil
}

func isAPIURL(u string) bool {
	lower := strings.ToLower(u)
	patterns := []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
