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

	// Use CommonCrawl index API
	apiURL := fmt.Sprintf(
		"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s/*&output=json",
		parsed.Host,
	)

	body, status, err := c.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("commoncrawl returned status %d", status)
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
