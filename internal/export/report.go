// apihunter/internal/export/report.go
package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apihunter/apihunter/internal/analyzer"
	"github.com/apihunter/apihunter/internal/models"
)

// ReportExporter generates summary reports
type ReportExporter struct{}

// NewReportExporter creates a new report exporter
func NewReportExporter() *ReportExporter {
	return &ReportExporter{}
}

// Export generates report files (markdown and JSON)
func (e *ReportExporter) Export(result *models.ScanResult, groups []analyzer.EndpointGroup, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// Calculate stats
	result.Statistics = e.calculateStats(result.Endpoints)

	// Generate markdown report
	md := e.generateMarkdown(result, groups)
	if err := os.WriteFile(filepath.Join(outputDir, "report.md"), []byte(md), 0644); err != nil {
		return err
	}

	// Generate JSON results
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "results.json"), jsonData, 0644)
}

func (e *ReportExporter) calculateStats(endpoints []models.Endpoint) models.ScanStats {
	stats := models.ScanStats{
		TotalURLs:       len(endpoints),
		UniqueEndpoints: len(endpoints),
	}

	for _, ep := range endpoints {
		switch ep.Risk {
		case models.RiskCritical:
			stats.CriticalCount++
		case models.RiskHigh:
			stats.HighCount++
		case models.RiskMedium:
			stats.MediumCount++
		case models.RiskLow:
			stats.LowCount++
		}
	}

	return stats
}

func (e *ReportExporter) generateMarkdown(result *models.ScanResult, groups []analyzer.EndpointGroup) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# APIHunter Report - %s\n\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s - %s\n\n", result.StartTime.Format("2006-01-02 15:04:05"), result.EndTime.Format("15:04:05")))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Count |\n"))
	sb.WriteString(fmt.Sprintf("|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Total Endpoints | %d |\n", result.Statistics.UniqueEndpoints))
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", result.Statistics.CriticalCount))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", result.Statistics.HighCount))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", result.Statistics.MediumCount))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n\n", result.Statistics.LowCount))

	// Module stats
	sb.WriteString("## Module Results\n\n")
	for name, stat := range result.ModuleStats {
		status := "OK"
		if stat.Error != "" {
			status = "ERROR: " + stat.Error
		}
		sb.WriteString(fmt.Sprintf("- **%s**: %d URLs (%.2fs) - %s\n", name, stat.URLs, stat.Duration.Seconds(), status))
	}
	sb.WriteString("\n")

	// Critical endpoints
	sb.WriteString("## Critical Endpoints\n\n")
	for _, ep := range result.Endpoints {
		if ep.Risk == models.RiskCritical {
			methods := strings.Join(ep.Methods, ", ")
			tags := strings.Join(ep.Tags, ", ")
			sb.WriteString(fmt.Sprintf("- `%s` %s [%s]\n", methods, ep.NormalizedPath, tags))
		}
	}
	sb.WriteString("\n")

	// High risk endpoints
	sb.WriteString("## High Risk Endpoints\n\n")
	for _, ep := range result.Endpoints {
		if ep.Risk == models.RiskHigh {
			methods := strings.Join(ep.Methods, ", ")
			tags := strings.Join(ep.Tags, ", ")
			sb.WriteString(fmt.Sprintf("- `%s` %s [%s]\n", methods, ep.NormalizedPath, tags))
		}
	}

	return sb.String()
}
