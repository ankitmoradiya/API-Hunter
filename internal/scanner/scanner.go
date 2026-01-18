// apihunter/internal/scanner/scanner.go
package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/apihunter/apihunter/internal/analyzer"
	"github.com/apihunter/apihunter/internal/auth"
	"github.com/apihunter/apihunter/internal/config"
	"github.com/apihunter/apihunter/internal/export"
	httpclient "github.com/apihunter/apihunter/internal/http"
	"github.com/apihunter/apihunter/internal/models"
	"github.com/apihunter/apihunter/internal/recon"
)

// Scanner orchestrates the entire scanning process
type Scanner struct {
	config *config.Config
	client *httpclient.Client
}

// NewScanner creates a new scanner
func NewScanner(cfg *config.Config) *Scanner {
	client := httpclient.NewClient(cfg.RateLimit.RequestsPerSecond, cfg.Timeout)

	// Set auth headers
	if cfg.Auth.Cookies != "" {
		client.SetCookies(cfg.Auth.Cookies)
	}
	if cfg.Auth.BearerToken != "" {
		client.SetHeader("Authorization", "Bearer "+cfg.Auth.BearerToken)
	}
	for _, h := range cfg.Auth.Headers {
		parts := splitHeader(h)
		if len(parts) == 2 {
			client.SetHeader(parts[0], parts[1])
		}
	}

	return &Scanner{
		config: cfg,
		client: client,
	}
}

// Run executes the full scan
func (s *Scanner) Run(ctx context.Context) error {
	fmt.Printf("[*] Starting reconnaissance on %s\n\n", s.config.Target)

	// Auto-login if credentials provided
	if s.config.Auth.Username != "" && s.config.Auth.Password != "" {
		if err := s.performAutoLogin(); err != nil {
			return fmt.Errorf("auto-login failed: %w", err)
		}
	}

	// Phase 1: Reconnaissance
	fmt.Println("[1/4] Running reconnaissance modules...")
	orchestrator := recon.NewOrchestrator(s.config, s.client)
	result, err := orchestrator.Run(ctx, s.config.Target)
	if err != nil {
		return fmt.Errorf("recon failed: %w", err)
	}

	for name, stat := range result.ModuleStats {
		status := "OK"
		if stat.Error != "" {
			status = "WARN"
		}
		fmt.Printf("    [%s] %s: %d URLs (%.2fs)\n", status, name, stat.URLs, stat.Duration.Seconds())
	}

	// Phase 2: Normalization
	fmt.Println("\n[2/4] Normalizing endpoints...")
	normalizer := analyzer.NewNormalizer()
	result.Endpoints = normalizer.Normalize(result.Endpoints)
	fmt.Printf("    Normalized to %d unique endpoints\n", len(result.Endpoints))

	// Phase 3: Analysis
	fmt.Println("\n[3/4] Analyzing endpoints...")
	inferrer := analyzer.NewInferrer()
	result.Endpoints = inferrer.InferMethods(result.Endpoints)

	tagger := analyzer.NewTagger()
	result.Endpoints = tagger.TagEndpoints(result.Endpoints)

	grouper := analyzer.NewGrouper()
	groups := grouper.GroupEndpoints(result.Endpoints)
	fmt.Printf("    Grouped into %d resource categories\n", len(groups))

	// Phase 4: Export
	fmt.Println("\n[4/4] Generating output files...")
	if err := s.exportResults(result, groups); err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Summary
	s.printSummary(result)

	return nil
}

func (s *Scanner) exportResults(result *models.ScanResult, groups []analyzer.EndpointGroup) error {
	for _, format := range s.config.Formats {
		switch format {
		case "openapi":
			if err := export.NewOpenAPIExporter().Export(result, groups, s.config.OutputDir); err != nil {
				return err
			}
			fmt.Printf("    Generated openapi.yaml\n")
		case "postman":
			if err := export.NewPostmanExporter().Export(result, groups, s.config.OutputDir); err != nil {
				return err
			}
			fmt.Printf("    Generated postman_collection.json\n")
		case "urls":
			if err := export.NewURLExporter().Export(result, s.config.OutputDir); err != nil {
				return err
			}
			fmt.Printf("    Generated URL lists\n")
		case "report":
			if err := export.NewReportExporter().Export(result, groups, s.config.OutputDir); err != nil {
				return err
			}
			fmt.Printf("    Generated report.md and results.json\n")
		}
	}
	return nil
}

func (s *Scanner) printSummary(result *models.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("  SCAN COMPLETE")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("\n  Total Endpoints: %d\n", len(result.Endpoints))
	fmt.Printf("  Critical: %d | High: %d | Medium: %d | Low: %d\n",
		result.Statistics.CriticalCount,
		result.Statistics.HighCount,
		result.Statistics.MediumCount,
		result.Statistics.LowCount)
	fmt.Printf("\n  Output saved to: %s\n\n", s.config.OutputDir)
}

func splitHeader(h string) []string {
	idx := strings.Index(h, ":")
	if idx == -1 {
		return nil
	}
	return []string{strings.TrimSpace(h[:idx]), strings.TrimSpace(h[idx+1:])}
}

// performAutoLogin handles automatic authentication
func (s *Scanner) performAutoLogin() error {
	fmt.Println("[*] Performing automatic login...")

	// Determine login URL
	loginURL := s.config.Auth.LoginURL
	if loginURL == "" {
		// If no login URL specified, try common paths
		loginURL = s.config.Target + "/login"
	}

	// Create auth config
	authConfig := &auth.Config{
		LoginURL:      loginURL,
		Username:      s.config.Auth.Username,
		Password:      s.config.Auth.Password,
		AuthType:      auth.AuthType(s.config.Auth.AuthType),
		UsernameField: s.config.Auth.UsernameField,
		PasswordField: s.config.Auth.PasswordField,
	}

	// Create authenticator and login
	authenticator := auth.NewAuthenticator(s.client, authConfig)
	result, err := authenticator.Login()
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("login failed: %s", result.Message)
	}

	// Apply cookies from login response
	if result.Cookies != "" {
		s.client.AppendCookies(result.Cookies)
		fmt.Printf("    [OK] Session cookies captured\n")
	}

	// Apply headers from login response (e.g., Bearer token)
	for k, v := range result.Headers {
		s.client.SetHeader(k, v)
		if k == "Authorization" {
			fmt.Printf("    [OK] Authorization token captured\n")
		}
	}

	fmt.Printf("    [OK] %s\n\n", result.Message)
	return nil
}
