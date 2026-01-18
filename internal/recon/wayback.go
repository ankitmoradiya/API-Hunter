// apihunter/internal/recon/wayback.go
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	httpclient "github.com/apihunter/apihunter/internal/http"
)

type WaybackModule struct {
	client *httpclient.Client
}

func NewWaybackModule(client *httpclient.Client) *WaybackModule {
	return &WaybackModule{client: client}
}

func (w *WaybackModule) Name() string {
	return "wayback"
}

func (w *WaybackModule) Run(ctx context.Context, target string) ([]string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=original",
		parsed.Host,
	)

	body, status, err := w.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("wayback returned status %d", status)
	}

	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	var urls []string
	for i, row := range results {
		if i == 0 { // Skip header row
			continue
		}
		if len(row) > 0 {
			u := row[0]
			if isAPIEndpoint(u) {
				urls = append(urls, u)
			}
		}
	}

	return urls, nil
}

func isAPIEndpoint(u string) bool {
	patterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/graphql", "/rest/", "/json/",
		".json", "/ajax/", "/rpc/",
	}
	lower := strings.ToLower(u)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return true // Include all for now, filter later
}
