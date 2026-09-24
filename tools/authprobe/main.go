// authprobe: unauthenticated access-control probe for API-Hunter results.
//
// Reads an API-Hunter results.json and checks, WITHOUT any auth header or
// cookie, whether each discovered endpoint is gated by authentication.
//
// SAFETY: this is read-safe. It never invokes a write handler. Read endpoints
// are probed with GET; write-only endpoints are probed with GET/OPTIONS purely
// to observe the auth gate (a 401/403 means protected). No POST/PUT/PATCH/DELETE
// is ever sent, so no data can be created, modified, or deleted.
//
// Usage:
//   go run ./tools/authprobe -in apihunter_output/results.json -out apihunter_output/authtest
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type endpoint struct {
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
	Risk    string   `json:"risk"`
}

type results struct {
	Endpoints []endpoint `json:"endpoints"`
}

type finding struct {
	URL      string
	Methods  string
	Risk     string
	Probe    string // method actually sent
	Status   int
	Location string
	BodyLen  int
	Class    string
}

func main() {
	in := flag.String("in", "apihunter_output/results.json", "API-Hunter results.json")
	out := flag.String("out", "apihunter_output/authtest", "output path prefix")
	conc := flag.Int("c", 6, "concurrency")
	rps := flag.Int("rps", 8, "max requests/sec")
	flag.Parse()

	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Println("read input:", err)
		os.Exit(1)
	}
	var res results
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Println("parse input:", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		// Do NOT follow redirects — a 302 to /sign-in is evidence of an auth gate.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: 10,
		},
	}

	ticker := time.NewTicker(time.Second / time.Duration(max(1, *rps)))
	defer ticker.Stop()

	sem := make(chan struct{}, *conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []finding

	for _, ep := range res.Endpoints {
		ep := ep
		wg.Add(1)
		sem <- struct{}{}
		<-ticker.C
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// Read-safe probe method: GET is non-mutating for every endpoint.
			probe := "GET"
			f := probeOne(client, probe, ep)
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Order: most interesting (exposed / reached without auth) first.
	rank := map[string]int{
		"EXPOSED (2xx)":      0,
		"REACHED (4xx noauth)": 1,
		"METHOD-NOT-ALLOWED": 2,
		"SERVER-ERROR (5xx)": 3,
		"NOT-FOUND":          4,
		"RATE-LIMITED":       5,
		"PROTECTED":          6,
		"ERROR":              7,
	}
	riskRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Class] != rank[findings[j].Class] {
			return rank[findings[i].Class] < rank[findings[j].Class]
		}
		return riskRank[findings[i].Risk] < riskRank[findings[j].Risk]
	})

	writeReport(*out, findings)
}

func probeOne(client *http.Client, method string, ep endpoint) finding {
	f := finding{URL: ep.URL, Methods: strings.Join(ep.Methods, ","), Risk: ep.Risk, Probe: method}

	req, err := http.NewRequest(method, ep.URL, nil)
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
	n, _ := resp.Body.Read(buf) // sample only; we record length class, not content
	f.BodyLen = n
	f.Status = resp.StatusCode
	f.Location = resp.Header.Get("Location")
	f.Class = classify(resp.StatusCode, f.Location)
	return f
}

func classify(status int, location string) string {
	loginRedirect := location != "" && (strings.Contains(strings.ToLower(location), "sign-in") ||
		strings.Contains(strings.ToLower(location), "login") ||
		strings.Contains(strings.ToLower(location), "auth"))
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

func writeReport(prefix string, findings []finding) {
	// counts
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Class]++
	}

	var b strings.Builder
	b.WriteString("# Unauthenticated Access-Control Probe\n\n")
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString("Read-safe probe (GET/OPTIONS only, no auth header/cookie). No write handler was invoked.\n\n")
	b.WriteString("## Summary\n\n| Class | Count |\n|---|---|\n")
	for _, k := range []string{"EXPOSED (2xx)", "REACHED (4xx noauth)", "METHOD-NOT-ALLOWED", "SERVER-ERROR (5xx)", "NOT-FOUND", "RATE-LIMITED", "PROTECTED", "ERROR"} {
		if counts[k] > 0 {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", k, counts[k]))
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

	_ = os.WriteFile(prefix+"_report.md", []byte(b.String()), 0o644)
	j, _ := json.MarshalIndent(findings, "", "  ")
	_ = os.WriteFile(prefix+"_results.json", j, 0o644)

	fmt.Println("=== Unauthenticated probe complete ===")
	for _, k := range []string{"EXPOSED (2xx)", "REACHED (4xx noauth)", "METHOD-NOT-ALLOWED", "SERVER-ERROR (5xx)", "NOT-FOUND", "RATE-LIMITED", "PROTECTED", "ERROR"} {
		if counts[k] > 0 {
			fmt.Printf("  %-22s %d\n", k, counts[k])
		}
	}
	fmt.Printf("\nReport: %s_report.md\n", prefix)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
