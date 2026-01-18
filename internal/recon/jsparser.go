// apihunter/internal/recon/jsparser.go
package recon

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	httpclient "github.com/apihunter/apihunter/internal/http"
)

type JSParserModule struct {
	client *httpclient.Client
}

func NewJSParserModule(client *httpclient.Client) *JSParserModule {
	return &JSParserModule{client: client}
}

func (j *JSParserModule) Name() string {
	return "jsparser"
}

func (j *JSParserModule) Run(ctx context.Context, target string) ([]string, error) {
	// First crawl to find JS files
	body, status, err := j.client.Get(target)
	if err != nil || status != 200 {
		return nil, err
	}

	baseURL, _ := url.Parse(target)
	jsFiles := j.extractJSFiles(string(body), baseURL)

	var allEndpoints []string
	for _, jsFile := range jsFiles {
		endpoints := j.parseJSFile(jsFile, baseURL)
		allEndpoints = append(allEndpoints, endpoints...)
	}

	return allEndpoints, nil
}

func (j *JSParserModule) extractJSFiles(html string, base *url.URL) []string {
	var files []string
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			ref, err := url.Parse(match[1])
			if err == nil {
				files = append(files, base.ResolveReference(ref).String())
			}
		}
	}
	return files
}

func (j *JSParserModule) parseJSFile(jsURL string, base *url.URL) []string {
	body, status, err := j.client.Get(jsURL)
	if err != nil || status != 200 {
		return nil
	}

	content := string(body)
	var endpoints []string

	// Pattern 1: API paths in strings
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"']+)["']`),
		regexp.MustCompile(`["'](/v[0-9]+/[^"']+)["']`),
		regexp.MustCompile(`["'](https?://[^"']+/api/[^"']+)["']`),
		regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`axios\.[a-z]+\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.get\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.post\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.put\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.delete\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`baseURL\s*[:=]\s*["']([^"']+)["']`),
		regexp.MustCompile(`endpoint\s*[:=]\s*["']([^"']+)["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if strings.HasPrefix(endpoint, "/") {
					endpoint = base.Scheme + "://" + base.Host + endpoint
				}
				if strings.HasPrefix(endpoint, "http") {
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	return endpoints
}
