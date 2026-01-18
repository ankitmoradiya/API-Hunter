package models

import "time"

type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
)

type Endpoint struct {
	URL            string            `json:"url"`
	Path           string            `json:"path"`
	NormalizedPath string            `json:"normalized_path"`
	Methods        []string          `json:"methods"`
	Parameters     []Parameter       `json:"parameters"`
	QueryParams    []Parameter       `json:"query_params"`
	Headers        map[string]string `json:"headers"`
	Source         string            `json:"source"`
	Risk           RiskLevel         `json:"risk"`
	Tags           []string          `json:"tags"`
	DiscoveredAt   time.Time         `json:"discovered_at"`
}

type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Example  string `json:"example,omitempty"`
}

type ScanResult struct {
	Target      string                `json:"target"`
	StartTime   time.Time             `json:"start_time"`
	EndTime     time.Time             `json:"end_time"`
	Endpoints   []Endpoint            `json:"endpoints"`
	JSFiles     []string              `json:"js_files"`
	Statistics  ScanStats             `json:"statistics"`
	ModuleStats map[string]ModuleStat `json:"module_stats"`
}

type ScanStats struct {
	TotalURLs       int `json:"total_urls"`
	UniqueEndpoints int `json:"unique_endpoints"`
	CriticalCount   int `json:"critical_count"`
	HighCount       int `json:"high_count"`
	MediumCount     int `json:"medium_count"`
	LowCount        int `json:"low_count"`
}

type ModuleStat struct {
	Name     string        `json:"name"`
	URLs     int           `json:"urls"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}
