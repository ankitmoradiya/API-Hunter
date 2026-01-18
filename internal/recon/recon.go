// apihunter/internal/recon/recon.go
package recon

import (
	"context"
	"sync"
	"time"

	"github.com/apihunter/apihunter/internal/config"
	httpclient "github.com/apihunter/apihunter/internal/http"
	"github.com/apihunter/apihunter/internal/models"
)

// Module interface for all recon modules
type Module interface {
	Name() string
	Run(ctx context.Context, target string) ([]string, error)
}

// Orchestrator runs all enabled modules
type Orchestrator struct {
	config  *config.Config
	client  *httpclient.Client
	modules []Module
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator(cfg *config.Config, client *httpclient.Client) *Orchestrator {
	o := &Orchestrator{
		config: cfg,
		client: client,
	}
	o.registerModules()
	return o
}

func (o *Orchestrator) registerModules() {
	if !o.config.Modules.ActiveOnly {
		if o.config.Modules.Wayback {
			o.modules = append(o.modules, NewWaybackModule(o.client))
		}
		if o.config.Modules.CommonCrawl {
			o.modules = append(o.modules, NewCommonCrawlModule(o.client))
		}
	}
	if !o.config.Modules.PassiveOnly {
		if o.config.Modules.Sitemap {
			o.modules = append(o.modules, NewSitemapModule(o.client))
		}
		if o.config.Modules.Crawler {
			o.modules = append(o.modules, NewCrawlerModule(o.client, o.config.CrawlDepth))
		}
		if o.config.Modules.JSParser {
			o.modules = append(o.modules, NewJSParserModule(o.client))
		}
	}
}

// Run executes all modules and collects results
func (o *Orchestrator) Run(ctx context.Context, target string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		Target:      target,
		StartTime:   time.Now(),
		ModuleStats: make(map[string]models.ModuleStat),
	}

	var allURLs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, mod := range o.modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			start := time.Now()
			urls, err := m.Run(ctx, target)

			stat := models.ModuleStat{
				Name:     m.Name(),
				Duration: time.Since(start),
				URLs:     len(urls),
			}
			if err != nil {
				stat.Error = err.Error()
			}

			mu.Lock()
			result.ModuleStats[m.Name()] = stat
			allURLs = append(allURLs, urls...)
			mu.Unlock()
		}(mod)
	}

	wg.Wait()
	result.EndTime = time.Now()

	// Deduplicate URLs
	seen := make(map[string]bool)
	for _, u := range allURLs {
		if !seen[u] {
			seen[u] = true
			result.Endpoints = append(result.Endpoints, models.Endpoint{URL: u})
		}
	}

	return result, nil
}
