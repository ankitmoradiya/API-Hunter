// apihunter/internal/recon/crawler.go
package recon

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	httpclient "github.com/apihunter/apihunter/internal/http"
)

type CrawlerModule struct {
	client   *httpclient.Client
	maxDepth int
	visited  map[string]bool
	mu       sync.Mutex
}

func NewCrawlerModule(client *httpclient.Client, maxDepth int) *CrawlerModule {
	return &CrawlerModule{
		client:   client,
		maxDepth: maxDepth,
		visited:  make(map[string]bool),
	}
}

func (c *CrawlerModule) Name() string {
	return "crawler"
}

func (c *CrawlerModule) Run(ctx context.Context, target string) ([]string, error) {
	var urls []string
	c.crawl(target, 0, &urls)
	return urls, nil
}

func (c *CrawlerModule) crawl(targetURL string, depth int, urls *[]string) {
	if depth > c.maxDepth {
		return
	}

	c.mu.Lock()
	if c.visited[targetURL] {
		c.mu.Unlock()
		return
	}
	c.visited[targetURL] = true
	c.mu.Unlock()

	body, status, err := c.client.Get(targetURL)
	if err != nil || status != 200 {
		return
	}

	*urls = append(*urls, targetURL)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	baseURL, _ := url.Parse(targetURL)

	// Extract links
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		linkURL := c.resolveURL(baseURL, href)
		if linkURL != "" && c.isSameDomain(baseURL, linkURL) {
			c.crawl(linkURL, depth+1, urls)
		}
	})

	// Extract form actions
	doc.Find("form[action]").Each(func(_ int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		if exists {
			linkURL := c.resolveURL(baseURL, action)
			if linkURL != "" {
				*urls = append(*urls, linkURL)
			}
		}
	})

	// Extract script sources
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists {
			linkURL := c.resolveURL(baseURL, src)
			if linkURL != "" {
				*urls = append(*urls, linkURL)
			}
		}
	})
}

func (c *CrawlerModule) resolveURL(base *url.URL, href string) string {
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func (c *CrawlerModule) isSameDomain(base *url.URL, target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	return parsed.Host == base.Host
}
