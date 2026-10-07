// Package secrets scans discovered JavaScript (and the target page itself) for
// leaked credentials — API keys, tokens, private keys, and connection strings
// that would impact the organization if disclosed publicly.
//
// It only fetches resources already discovered by the scan (public JS bundles
// and the target URL) and never sends credentials of its own. Findings are
// reported in full so an analyst can verify and, where authorized, rotate them.
package secrets

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Getter is the subset of the HTTP client the scanner needs (satisfied by
// internal/http.Client). Decoupled so the scanner is testable.
type Getter interface {
	Get(url string) ([]byte, int, error)
}

// Finding is one detected secret.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Source   string `json:"source"` // URL of the JS/HTML file it was found in
	Line     int    `json:"line"`
	Match    string `json:"match"`   // full matched text (the evidence)
	Snippet  string `json:"snippet"` // surrounding source line, trimmed
}

// Summary is the count breakdown shown after the phase runs.
type Summary struct {
	FilesScanned int
	Total        int
	Critical     int
	High         int
	Medium       int
}

const maxBodyScan = 50 << 20 // skip absurdly large bodies

// Scan fetches each source (JS files + target page), scans the bodies, writes
// secrets_report.md and secrets_results.json into outputDir, and returns a
// summary. conc bounds concurrent fetches.
func Scan(client Getter, sources []string, outputDir string, conc int) (Summary, error) {
	if conc < 1 {
		conc = 5
	}

	// De-duplicate the source list (target page may also appear as a JS host).
	seenSrc := make(map[string]bool)
	var uniq []string
	for _, s := range sources {
		if s != "" && !seenSrc[s] {
			seenSrc[s] = true
			uniq = append(uniq, s)
		}
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []Finding
	scanned := 0

	for _, src := range uniq {
		src := src
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			body, status, err := client.Get(src)
			if err != nil || status != 200 || len(body) == 0 || len(body) > maxBodyScan {
				return
			}
			fs := scanContent(src, string(body))

			mu.Lock()
			scanned++
			findings = append(findings, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	findings = dedupe(findings)
	sortFindings(findings)

	sum := Summary{FilesScanned: scanned, Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			sum.Critical++
		case SevHigh:
			sum.High++
		case SevMedium:
			sum.Medium++
		}
	}

	if err := writeReport(outputDir, findings, sum); err != nil {
		return sum, err
	}
	return sum, nil
}

// scanContent runs every rule over one file's content.
func scanContent(source, content string) []Finding {
	var out []Finding
	for _, rule := range rules {
		for _, idx := range rule.Re.FindAllStringSubmatchIndex(content, -1) {
			full := content[idx[0]:idx[1]]

			// Value used for filtering: the capture group if present, else full match.
			value := full
			if rule.Group > 0 && len(idx) > 2*rule.Group+1 && idx[2*rule.Group] >= 0 {
				value = content[idx[2*rule.Group]:idx[2*rule.Group+1]]
			}

			if rule.Generic && !looksLikeSecret(value) {
				continue
			}
			if isPlaceholder(value) {
				continue
			}

			out = append(out, Finding{
				Rule:     rule.Name,
				Severity: rule.Severity,
				Source:   source,
				Line:     lineOf(content, idx[0]),
				Match:    trim(full, 400),
				Snippet:  snippetAround(content, idx[0], idx[1]),
			})
		}
	}
	return out
}

// looksLikeSecret filters low-signal generic matches: a real secret has mixed
// character classes and non-trivial entropy, and is not a path/word.
func looksLikeSecret(v string) bool {
	if len(v) < 8 {
		return false
	}
	if strings.ContainsAny(v, "/\\ <>(){}") {
		return false
	}
	var hasLetter, hasDigitOrSym bool
	for _, r := range v {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		case (r >= '0' && r <= '9') || strings.ContainsRune("-_=+./", r):
			hasDigitOrSym = true
		}
	}
	if !(hasLetter && hasDigitOrSym) && len(v) < 16 {
		return false
	}
	return shannonEntropy(v) >= 3.0
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

// placeholderTokens are strong, word-like indicators of a non-real value. They
// are matched as substrings, so they must be distinctive enough that a genuine
// high-entropy secret is unlikely to contain them (e.g. "abcdef"/"123456" are
// deliberately excluded — real keys can contain those sequences).
var placeholderTokens = []string{
	"example", "your_", "yourkey", "your-key", "placeholder", "changeme",
	"xxxx", "dummy", "sample", "test_key", "testkey", "redacted",
	"enter_your", "<your", "notarealkey", "fakekey", "replace_me",
	"process.env", "import.meta",
}

func isPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, t := range placeholderTokens {
		if strings.Contains(lv, t) {
			return true
		}
	}
	// All-same-character values (aaaaaa, ******) are not real secrets.
	if len(v) > 0 {
		all := true
		for i := 1; i < len(v); i++ {
			if v[i] != v[0] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func lineOf(content string, pos int) int {
	if pos > len(content) {
		pos = len(content)
	}
	return strings.Count(content[:pos], "\n") + 1
}

// snippetAround returns the source line(s) spanning the match, trimmed and capped.
func snippetAround(content string, start, end int) string {
	ls := strings.LastIndexByte(content[:start], '\n') + 1
	le := end
	if nl := strings.IndexByte(content[end:], '\n'); nl >= 0 {
		le = end + nl
	} else {
		le = len(content)
	}
	if le < ls {
		le = ls
	}
	return trim(strings.TrimSpace(content[ls:le]), 240)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func dedupe(in []Finding) []Finding {
	seen := make(map[string]bool)
	var out []Finding
	for _, f := range in {
		key := f.Rule + "|" + f.Source + "|" + f.Match
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func sortFindings(f []Finding) {
	sev := map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2}
	sort.SliceStable(f, func(i, j int) bool {
		if sev[f[i].Severity] != sev[f[j].Severity] {
			return sev[f[i].Severity] < sev[f[j].Severity]
		}
		if f[i].Source != f[j].Source {
			return f[i].Source < f[j].Source
		}
		return f[i].Line < f[j].Line
	})
}

func writeReport(outputDir string, findings []Finding, sum Summary) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# JavaScript Secret Scan\n\n")
	b.WriteString(fmt.Sprintf("**Files scanned:** %d\n\n", sum.FilesScanned))
	b.WriteString("Scans publicly reachable JavaScript bundles (and the target page) for leaked credentials. ")
	b.WriteString("Values are shown in full so you can verify them; treat this report as sensitive.\n\n")

	b.WriteString("## Summary\n\n| Severity | Count |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| Critical | %d |\n| High | %d |\n| Medium | %d |\n| **Total** | **%d** |\n\n",
		sum.Critical, sum.High, sum.Medium, sum.Total))

	if sum.Total == 0 {
		b.WriteString("No secrets detected.\n")
	} else {
		b.WriteString("## Findings\n\n")
		for _, f := range findings {
			b.WriteString(fmt.Sprintf("### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Rule))
			b.WriteString(fmt.Sprintf("- **Source:** %s (line %d)\n", f.Source, f.Line))
			b.WriteString(fmt.Sprintf("- **Match:** `%s`\n", f.Match))
			b.WriteString(fmt.Sprintf("- **Context:** `%s`\n\n", f.Snippet))
		}
	}

	if err := os.WriteFile(filepath.Join(outputDir, "secrets_report.md"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	j, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "secrets_results.json"), j, 0o644)
}
