// apihunter/internal/recon/jsparser.go
package recon

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	httpclient "github.com/apihunter/apihunter/internal/http"
)

type JSParserModule struct {
	client *httpclient.Client
}

func NewJSParserModule(client *httpclient.Client) *JSParserModule {
	return &JSParserModule{client: client}
}

func (j *JSParserModule) Name() string {
	return "jsparser"
}

// maxJSFiles caps how many script files we fetch/parse (index + lazy chunks).
const maxJSFiles = 40

var (
	scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

	// Base API URL declared in the bundle's environment config, e.g.
	//   apiUrl:"https://host/api/"   baseUrl = 'https://host'
	baseURLRe = regexp.MustCompile(`(?i)(?:api_?base_?url|api_?url|base_?url|api_?endpoint|api_?host|server_?url)\s*[:=]\s*["` + "`" + `']\s*(https?://[^"` + "`" + `'\s]+)`)

	// Endpoint literals concatenated onto a known base variable:
	//   apiUrl+"Controller/Action"      apiBaseUrl + 'Clients/ByUser'
	concatRe = regexp.MustCompile(`(?i)(?:api_?url|api_?base_?url|base_?url|api_?endpoint|endpoint|api_?host|server_?url)\s*\+\s*["'` + "`" + `]([A-Za-z0-9][A-Za-z0-9_/.-]*)`)

	// Endpoint literals in a template string after the base var:
	//   `${apiUrl}Clients/ByUser/${id}`  ->  apiUrl}Clients/ByUser/
	templateRe = regexp.MustCompile(`(?i)(?:api_?url|api_?base_?url|base_?url|api_?endpoint|endpoint|api_?host|server_?url)\}([A-Za-z0-9][A-Za-z0-9_/.-]*)`)

	// Path fragments stored as environment properties:
	//   forgotPasswordApiUrl:"SignIn/ForgotPassword"
	propApiRe = regexp.MustCompile(`(?i)[A-Za-z0-9_]*(?:api_?url|api_?path|endpoint)\s*:\s*["']([A-Za-z0-9][A-Za-z0-9_/.-]+)["']`)

	// Absolute API-looking paths.
	apiPathRe = regexp.MustCompile(`["'](/(?:api|v[0-9]+|rest|graphql)[A-Za-z0-9_/.-]*)["']`)

	// Fully-qualified URLs.
	fullURLRe = regexp.MustCompile(`["'](https?://[^"'\s]+)["']`)

	// Generic .NET/Java style Controller/Action literals: PascalCase word / segment(s).
	ctrlActionRe = regexp.MustCompile(`["']([A-Z][A-Za-z0-9]+(?:/[A-Za-z0-9_-]+)+)["']`)

	// References to additional script chunks so we can follow lazy-loaded modules.
	jsChunkRe = regexp.MustCompile(`["']([A-Za-z0-9_./-]+\.js)["']`)

	assetExtRe = regexp.MustCompile(`(?i)\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|json|webp|mp4|webm|scss|less)(\?|$)`)

	// Date/time format strings (e.g. "DD/MM/YYYY", "HH/mm/ss") get caught by the
	// Controller/Action pattern but are not endpoints.
	dateFormatRe = regexp.MustCompile(`(?i)^(d{1,4}|m{1,4}|y{2,4}|h{1,2}|s{1,2}|a)(/(d{1,4}|m{1,4}|y{2,4}|h{1,2}|s{1,2}|a))+$`)
)

func (j *JSParserModule) Run(ctx context.Context, target string) ([]string, error) {
	body, status, err := j.client.Get(target)
	if err != nil || status != 200 {
		return nil, err
	}

	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Collect script files from the entry HTML, then fetch each (following a
	// bounded number of lazy-loaded chunks referenced inside them).
	queue := j.extractJSFiles(string(body), base)
	fetched := make(map[string]bool)
	var contents []string

	for len(queue) > 0 && len(fetched) < maxJSFiles {
		f := queue[0]
		queue = queue[1:]
		if fetched[f] {
			continue
		}
		fetched[f] = true

		b, st, err := j.client.Get(f)
		if err != nil || st != 200 {
			continue
		}
		content := string(b)
		contents = append(contents, content)

		// Discover further chunk files referenced within this script.
		for _, m := range jsChunkRe.FindAllStringSubmatch(content, -1) {
			ref, err := url.Parse(m[1])
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref).String()
			if !fetched[abs] && sameHost(base, abs) {
				queue = append(queue, abs)
			}
		}
	}

	// Discover the API base URL (often a different host than the site itself).
	apiBase := j.discoverAPIBase(contents)

	// Only endpoints on the target's own hosts are in scope; third-party
	// constant URLs (XML namespaces, CDN/doc links bundled by libraries) are noise.
	allowed := map[string]bool{base.Host: true}
	if apiBase != nil {
		allowed[apiBase.Host] = true
	}

	seen := make(map[string]bool)
	var endpoints []string
	add := func(raw string) {
		if u := j.resolve(raw, apiBase, base, allowed); u != "" && !seen[u] {
			seen[u] = true
			endpoints = append(endpoints, u)
		}
	}

	extractors := []*regexp.Regexp{concatRe, templateRe, propApiRe, apiPathRe, fullURLRe, ctrlActionRe}
	for _, content := range contents {
		for _, re := range extractors {
			for _, m := range re.FindAllStringSubmatch(content, -1) {
				if len(m) > 1 {
					add(m[1])
				}
			}
		}
	}

	return endpoints, nil
}

func (j *JSParserModule) extractJSFiles(html string, base *url.URL) []string {
	var files []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			if ref, err := url.Parse(m[1]); err == nil {
				files = append(files, base.ResolveReference(ref).String())
			}
		}
	}
	return files
}

// discoverAPIBase returns the first API base URL declared in the bundles, or nil.
func (j *JSParserModule) discoverAPIBase(contents []string) *url.URL {
	for _, content := range contents {
		if m := baseURLRe.FindStringSubmatch(content); len(m) > 1 {
			if u, err := url.Parse(strings.TrimSpace(m[1])); err == nil && u.Host != "" {
				return u
			}
		}
	}
	return nil
}

// resolve turns a raw match into an absolute endpoint URL, or "" if it should be
// dropped. Only URLs whose host is in `allowed` (the target site + its API host)
// are kept, which filters out third-party constant URLs bundled by libraries.
func (j *JSParserModule) resolve(raw string, apiBase, site *url.URL, allowed map[string]bool) string {
	raw = strings.TrimSpace(raw)
	// Cut off any template-literal remnant.
	if i := strings.IndexAny(raw, "${`"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimRight(raw, "/.")
	if len(raw) < 3 || strings.ContainsAny(raw, " <>()[]{}\\") {
		return ""
	}
	if dateFormatRe.MatchString(raw) {
		return ""
	}

	var full string
	switch {
	case strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"):
		u, err := url.Parse(raw)
		if err != nil || !allowed[u.Host] {
			return "" // off-scope host (XML namespace, CDN, docs) — not an endpoint
		}
		full = raw
	case strings.HasPrefix(raw, "/"):
		full = site.Scheme + "://" + site.Host + raw
	default:
		// Relative Controller/Action — must look path-like (a slash or PascalCase),
		// otherwise it's probably not an endpoint.
		if !strings.Contains(raw, "/") && !(raw[0] >= 'A' && raw[0] <= 'Z') {
			return ""
		}
		if apiBase != nil {
			full = strings.TrimRight(apiBase.String(), "/") + "/" + raw
		} else {
			full = site.Scheme + "://" + site.Host + "/" + raw
		}
	}

	if assetExtRe.MatchString(full) {
		return ""
	}
	return full
}

func sameHost(base *url.URL, target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	return u.Host == "" || u.Host == base.Host
}
