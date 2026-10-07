// Package authcheck probes discovered endpoints to determine whether they
// enforce authentication, re-requesting each one with NO session (no
// Authorization header, no cookies).
//
// SAFETY: read-safe by design. Every probe uses GET only, which is non-mutating
// for any correctly implemented endpoint, so no write handler (POST/PUT/PATCH/
// DELETE) is ever invoked and no data can be created, modified, or deleted.
// Redirects are deliberately NOT followed: a 302 to /sign-in is evidence of an
// auth gate, which the main crawler's redirect-following client would hide.
package authcheck

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apihunter/apihunter/internal/models"
)

// Finding is the access-control result for a single endpoint.
type Finding struct {
	URL      string `json:"url"`
	Methods  string `json:"methods"`
	Risk     string `json:"risk"`
	Probe    string `json:"probe"` // method actually sent (always GET)
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
	BodyLen  int    `json:"body_len"`
	Class    string `json:"class"`
}

// Summary holds the counts shown to the user after the phase runs.
type Summary struct {
	Total   int
	Exposed int // EXPOSED (2xx) + REACHED (4xx noauth)
	Counts  map[string]int
}

var classOrder = []string{
	"EXPOSED (2xx)",
	"REACHED (4xx noauth)",
	"METHOD-NOT-ALLOWED",
	"SERVER-ERROR (5xx)",
	"NOT-FOUND",
	"RATE-LIMITED",
	"PROTECTED",
	"ERROR",
}

// Run probes every endpoint in result and writes authtest_report.md and
// authtest_results.json into outputDir. rps/conc bound the request rate.
func Run(result *models.ScanResult, outputDir string, rps, conc int) (Summary, error) {
	if rps < 1 {
		rps = 8
	}
	if conc < 1 {
		conc = 6
	}

	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: 10,
		},
	}

	ticker := time.NewTicker(time.Second / time.Duration(rps))
	defer ticker.Stop()

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []Finding

	for _, ep := range result.Endpoints {
		ep := ep
		wg.Add(1)
		sem <- struct{}{}
		<-ticker.C
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f := probeOne(client, ep)
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
		}()
	}
	wg.Wait()

	rank := map[string]int{}
	for i, c := range classOrder {
		rank[c] = i
	}
	riskRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Class] != rank[findings[j].Class] {
			return rank[findings[i].Class] < rank[findings[j].Class]
		}
		return riskRank[findings[i].Risk] < riskRank[findings[j].Risk]
	})

	sum := Summary{Total: len(findings), Counts: map[string]int{}}
	for _, f := range findings {
		sum.Counts[f.Class]++
	}
	sum.Exposed = sum.Counts["EXPOSED (2xx)"] + sum.Counts["REACHED (4xx noauth)"]

	if err := writeReport(outputDir, result.Target, findings, sum); err != nil {
		return sum, err
	}
	return sum, nil
}

func probeOne(client *http.Client, ep models.Endpoint) Finding {
	f := Finding{URL: ep.URL, Methods: strings.Join(ep.Methods, ","), Risk: string(ep.Risk), Probe: "GET"}

	req, err := http.NewRequest("GET", ep.URL, nil)
	if err != nil {
		f.Class = "ERROR"
		return f
	}
	// Explicitly unauthenticated: no Authorization, no Cookie.
	req.Header.Set("User-Agent", "APIHunter-AuthProbe/1.0 (authorized access-control test)")
	req.Header.Set("Accept", "application/json, */*")

	resp, err := client.Do(req)
	if err != nil {
		f.Class = "ERROR"
		f.Location = err.Error()
		return f
	}
	defer resp.Body.Close()
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf) // sample only; record length class, not content
	f.BodyLen = n
	f.Status = resp.StatusCode
	f.Location = resp.Header.Get("Location")
	f.Class = classify(resp.StatusCode, f.Location)
	return f
}

func classify(status int, location string) string {
	loc := strings.ToLower(location)
	loginRedirect := location != "" && (strings.Contains(loc, "sign-in") ||
		strings.Contains(loc, "login") || strings.Contains(loc, "auth"))
	switch {
	case status == 401 || status == 403:
		return "PROTECTED"
	case (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) && loginRedirect:
		return "PROTECTED"
	case status >= 200 && status < 300:
		return "EXPOSED (2xx)"
	case status == 405:
		return "METHOD-NOT-ALLOWED"
	case status == 404:
		return "NOT-FOUND"
	case status == 429:
		return "RATE-LIMITED"
	case status == 400 || status == 422 || status == 415:
		return "REACHED (4xx noauth)"
	case status >= 500:
		return "SERVER-ERROR (5xx)"
	default:
		return fmt.Sprintf("OTHER (%d)", status)
	}
}

func writeReport(outputDir, target string, findings []Finding, sum Summary) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# Unauthenticated Access-Control Probe\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n\n", target))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString("Read-safe probe (GET only, no auth header/cookie, redirects not followed). No write handler was invoked.\n\n")
	b.WriteString("## Summary\n\n| Class | Count |\n|---|---|\n")
	for _, k := range classOrder {
		if sum.Counts[k] > 0 {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", k, sum.Counts[k]))
		}
	}
	b.WriteString("\n**EXPOSED (2xx)** = returned data with no authentication — likely broken access control.\n")
	b.WriteString("**REACHED (4xx noauth)** = handler/validation ran unauthenticated (auth gate likely absent; GET returned a non-401/403 client error).\n")
	b.WriteString("**METHOD-NOT-ALLOWED** = route exists but rejected GET; its real (write) method needs a method-accurate test to confirm the auth gate.\n\n")

	b.WriteString("## Findings\n\n| Class | Risk | Status | Len | Real methods | URL |\n|---|---|---|---|---|---|\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %s | %s |\n",
			f.Class, f.Risk, f.Status, f.BodyLen, f.Methods, f.URL))
	}

	if err := os.WriteFile(filepath.Join(outputDir, "authtest_report.md"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	j, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "authtest_results.json"), j, 0o644)
}
