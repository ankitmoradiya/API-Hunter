package main

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "apihunter",
	Short: "API reconnaissance and documentation tool",
	Long: `APIHunter discovers API endpoints from multiple sources
and generates security-testing-ready documentation.

Examples:
  apihunter scan -u https://api.example.com
  apihunter scan -u https://app.example.com -c "session=abc"`,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
