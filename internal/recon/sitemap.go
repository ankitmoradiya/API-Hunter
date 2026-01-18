// apihunter/internal/recon/sitemap.go
package recon

import (
	"context"
	"regexp"
	"strings"

	httpclient "github.com/apihunter/apihunter/internal/http"
)

type SitemapModule struct {
	client *httpclient.Client
}

func NewSitemapModule(client *httpclient.Client) *SitemapModule {
	return &SitemapModule{client: client}
}

func (s *SitemapModule) Name() string {
	return "sitemap"
}

// Common sitemap path variations
var sitemapPaths = []string{
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/sitemap1.xml",
	"/sitemap-index.xml",
	"/sitemaps/sitemap.xml",
	"/sitemap/sitemap.xml",
	"/sitemap.xml.gz",
	"/sitemap_index.xml.gz",
	"/sitemap.php",
	"/sitemap.txt",
	"/sitemap",
	"/site-map.xml",
	"/sitemapindex.xml",
	"/sitemap/index.xml",
	"/post-sitemap.xml",
	"/page-sitemap.xml",
	"/product-sitemap.xml",
	"/category-sitemap.xml",
	"/news-sitemap.xml",
	"/video-sitemap.xml",
	"/image-sitemap.xml",
}

func (s *SitemapModule) Run(ctx context.Context, target string) ([]string, error) {
	var urls []string
	seen := make(map[string]bool)

	// Fetch robots.txt (may contain sitemap references)
	robotsURLs := s.fetchRobots(target)
	for _, u := range robotsURLs {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	// Try common sitemap path variations
	for _, path := range sitemapPaths {
		sitemapURLs := s.fetchSitemap(target + path)
		for _, u := range sitemapURLs {
			if !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}

	return urls, nil
}

func (s *SitemapModule) fetchRobots(target string) []string {
	body, status, err := s.client.Get(target + "/robots.txt")
	if err != nil || status != 200 {
		return nil
	}

	var urls []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			path = strings.TrimSpace(strings.TrimPrefix(path, "disallow:"))
			if path != "" && path != "/" {
				urls = append(urls, target+path)
			}
		}
		if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			sitemapURL := strings.TrimSpace(strings.TrimPrefix(line, "Sitemap:"))
			sitemapURL = strings.TrimSpace(strings.TrimPrefix(sitemapURL, "sitemap:"))
			urls = append(urls, s.fetchSitemap(sitemapURL)...)
		}
	}
	return urls
}

func (s *SitemapModule) fetchSitemap(sitemapURL string) []string {
	body, status, err := s.client.Get(sitemapURL)
	if err != nil || status != 200 {
		return nil
	}

	var urls []string
	locRegex := regexp.MustCompile(`<loc>([^<]+)</loc>`)
	matches := locRegex.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, match[1])
		}
	}
	return urls
}
