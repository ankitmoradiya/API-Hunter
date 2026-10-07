package config

import (
	"net/url"
	"strings"
	"time"
)

// RunFolderName builds a filesystem-safe, per-scan folder name of the form
// "<host>_<DD-Mon-YYYY>_<HH-MMAM/PM>", e.g. "xyz.abc.com_23-Mar-2026_11-30PM".
//
// A colon is illegal in Windows paths, so the time uses a hyphen (11-30PM)
// rather than the usual 11:30PM. Any other character disallowed on Windows
// (<>:"/\|?*) or whitespace in the host is replaced with '_'.
func RunFolderName(target string, t time.Time) string {
	host := hostFromTarget(target)
	stamp := t.Format("02-Jan-2006_03-04PM")
	return sanitizeForPath(host) + "_" + stamp
}

func hostFromTarget(target string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		return "target"
	}
	// Ensure url.Parse treats it as absolute so Host is populated.
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		// Host may include a port (host:8443); keep it but it will be sanitized.
		return u.Host
	}
	return s
}

// sanitizeForPath replaces characters that are invalid in Windows file names
// (and whitespace) with underscores.
func sanitizeForPath(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<', '>', ':', '"', '/', '\\', '|', '?', '*', ' ', '\t', '\n', '\r':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		return "target"
	}
	return out
}
