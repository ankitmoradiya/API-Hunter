package config

import "time"

type Config struct {
	Target     string
	OutputDir  string // base directory; each scan creates a timestamped run folder inside it
	RunDir     string // resolved per-scan folder (<host>_<date>_<time>); set at scan start
	Formats    []string
	Auth       AuthConfig
	RateLimit  RateLimitConfig
	Modules    ModulesConfig
	CrawlDepth int
	Timeout    time.Duration
	Verbose    bool
	Quiet      bool
	AuthCheck  bool // probe discovered endpoints for missing authentication
	Secrets    bool // scan discovered JavaScript (and target page) for leaked secrets
}

type AuthConfig struct {
	Cookies     string
	Headers     []string
	BearerToken string
	// Auto-login settings
	LoginURL      string
	Username      string
	Password      string
	AuthType      string // "form", "json", "basic"
	UsernameField string // Form field name (default: "username")
	PasswordField string // Form field name (default: "password")
}

type RateLimitConfig struct {
	RequestsPerSecond int
	Threads           int
	Delay             time.Duration
	Adaptive          bool
}

type ModulesConfig struct {
	Wayback     bool
	CommonCrawl bool
	OTX         bool
	URLScan     bool
	Crawler     bool
	JSParser    bool
	Sitemap     bool
	PassiveOnly bool
	ActiveOnly  bool
}

func DefaultConfig() *Config {
	return &Config{
		OutputDir:  "./apihunter_output",
		Formats:    []string{"openapi", "postman", "urls", "report"},
		CrawlDepth: 3,
		Timeout:    30 * time.Second,
		AuthCheck:  true,
		Secrets:    true,
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 10,
			Threads:           5,
			Delay:             0,
			Adaptive:          true,
		},
		Modules: ModulesConfig{
			Wayback:     true,
			CommonCrawl: true,
			OTX:         true,
			URLScan:     true,
			Crawler:     true,
			JSParser:    true,
			Sitemap:     true,
		},
	}
}
