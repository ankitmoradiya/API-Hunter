package main

import (
	"fmt"
	"time"

	"github.com/apihunter/apihunter/internal/config"
	scannerPkg "github.com/apihunter/apihunter/internal/scanner"
	"github.com/spf13/cobra"
)

var cfg = config.DefaultConfig()

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform API reconnaissance on a target",
	Long: `Scan a target URL for API endpoints using multiple reconnaissance techniques.

Examples:
  apihunter scan -u https://api.example.com
  apihunter scan -u https://api.example.com --passive-only
  apihunter scan -u https://api.example.com -c "session=abc" -r 5

Auto-login examples:
  apihunter scan -u https://app.example.com --login-url https://app.example.com/login -U admin -P password123
  apihunter scan -u https://api.example.com --login-url https://api.example.com/auth/login -U user@email.com -P pass --auth-type json
  apihunter scan -u https://app.example.com -U admin -P password --auth-type basic`,
	RunE: runScan,
}

func init() {
	// Target
	scanCmd.Flags().StringVarP(&cfg.Target, "url", "u", "", "Target URL (required)")
	scanCmd.MarkFlagRequired("url")

	// Manual auth (cookies/headers)
	scanCmd.Flags().StringVarP(&cfg.Auth.Cookies, "cookie", "c", "", "Cookies to include")
	scanCmd.Flags().StringArrayVarP(&cfg.Auth.Headers, "header", "H", nil, "Headers to include")
	scanCmd.Flags().StringVar(&cfg.Auth.BearerToken, "auth-bearer", "", "Bearer token")

	// Auto-login
	scanCmd.Flags().StringVar(&cfg.Auth.LoginURL, "login-url", "", "Login URL for automatic authentication")
	scanCmd.Flags().StringVarP(&cfg.Auth.Username, "username", "U", "", "Username for auto-login")
	scanCmd.Flags().StringVarP(&cfg.Auth.Password, "password", "P", "", "Password for auto-login")
	scanCmd.Flags().StringVar(&cfg.Auth.AuthType, "auth-type", "form", "Auth type: form, json, basic")
	scanCmd.Flags().StringVar(&cfg.Auth.UsernameField, "username-field", "username", "Form field name for username")
	scanCmd.Flags().StringVar(&cfg.Auth.PasswordField, "password-field", "password", "Form field name for password")

	// Modules
	scanCmd.Flags().BoolVar(&cfg.Modules.PassiveOnly, "passive-only", false, "Only passive recon")
	scanCmd.Flags().BoolVar(&cfg.Modules.ActiveOnly, "active-only", false, "Only active recon")
	scanCmd.Flags().IntVar(&cfg.CrawlDepth, "crawl-depth", 3, "Max crawl depth")

	// Rate limiting
	scanCmd.Flags().IntVarP(&cfg.RateLimit.RequestsPerSecond, "rate", "r", 10, "Requests per second")
	scanCmd.Flags().IntVarP(&cfg.RateLimit.Threads, "threads", "t", 5, "Concurrent connections")
	scanCmd.Flags().DurationVar(&cfg.RateLimit.Delay, "delay", 0, "Delay between requests")
	scanCmd.Flags().BoolVar(&cfg.RateLimit.Adaptive, "adaptive", true, "Adaptive rate limiting")

	// Output
	scanCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "./apihunter_output", "Output directory")
	scanCmd.Flags().StringSliceVarP(&cfg.Formats, "format", "f", []string{"openapi", "postman", "urls", "report"}, "Output formats")
	scanCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().BoolVarP(&cfg.Quiet, "quiet", "q", false, "Minimal output")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if !cfg.Quiet {
		fmt.Printf("APIHunter v%s\n", version)
		fmt.Printf("Target: %s\n", cfg.Target)
		fmt.Printf("Starting scan at %s\n\n", time.Now().Format(time.RFC3339))
	}

	scanner := scannerPkg.NewScanner(cfg)
	return scanner.Run(cmd.Context())
}
