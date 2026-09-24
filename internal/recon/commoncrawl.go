// apihunter/internal/recon/commoncrawl.go
package recon

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strings"

	httpclient "github.com/apihunter/apihunter/internal/http"
)

type CommonCrawlModule struct {
	client *httpclient.Client
}

func NewCommonCrawlModule(client *httpclient.Client) *CommonCrawlModule {
	return &CommonCrawlModule{client: client}
}

func (c *CommonCrawlModule) Name() string {
	return "commoncrawl"
}

func (c *CommonCrawlModule) Run(ctx context.Context, target string) ([]string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Resolve the latest available index (the previously hardcoded collection
	// eventually 404s as CommonCrawl publishes new crawls).
	indexAPI := c.latestIndexAPI()

	apiURL := fmt.Sprintf("%s?url=%s/*&output=json", indexAPI, parsed.Host)

	body, status, err := c.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("commoncrawl returned status %d (index %s)", status, indexAPI)
	}

	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		// Extract URL from JSON line
		if idx := strings.Index(line, `"url": "`); idx != -1 {
			start := idx + 8
			end := strings.Index(line[start:], `"`)
			if end != -1 {
				urls = append(urls, line[start:start+end])
			}
		}
	}

	return urls, nil
}

// latestIndexAPI queries CommonCrawl's collection list and returns the newest
// cdx-api endpoint. Falls back to a known-recent index if the lookup fails.
func (c *CommonCrawlModule) latestIndexAPI() string {
	const fallback = "https://index.commoncrawl.org/CC-MAIN-2025-08-index"

	body, status, err := c.client.Get("https://index.commoncrawl.org/collinfo.json")
	if err != nil || status != 200 {
		return fallback
	}
	// collinfo.json is newest-first; grab the first "cdx-api" value.
	if idx := strings.Index(string(body), `"cdx-api":`); idx != -1 {
		rest := string(body)[idx+len(`"cdx-api":`):]
		start := strings.Index(rest, `"`)
		if start != -1 {
			rest = rest[start+1:]
			if end := strings.Index(rest, `"`); end != -1 {
				return rest[:end]
			}
		}
	}
	return fallback
}
