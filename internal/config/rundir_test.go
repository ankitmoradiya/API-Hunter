package config

import (
	"strings"
	"testing"
	"time"
)

func TestRunFolderName(t *testing.T) {
	ts := time.Date(2026, time.March, 23, 23, 30, 0, 0, time.UTC)

	cases := map[string]string{
		"https://xyz.abc.com":      "xyz.abc.com_23-Mar-2026_11-30PM",
		"http://xyz.abc.com:8443/": "xyz.abc.com_8443_23-Mar-2026_11-30PM",
		"xyz.abc.com":              "xyz.abc.com_23-Mar-2026_11-30PM",
	}
	for in, want := range cases {
		if got := RunFolderName(in, ts); got != want {
			t.Errorf("RunFolderName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunFolderNameNoIllegalChars(t *testing.T) {
	ts := time.Date(2026, time.March, 23, 23, 30, 0, 0, time.UTC)
	got := RunFolderName("https://user:pass@h.example.com:9000/path?x=1", ts)
	if strings.ContainsAny(got, `<>:"/\|?* `) {
		t.Errorf("folder name contains an illegal/whitespace character: %q", got)
	}
}

func TestRunFolderNameEmpty(t *testing.T) {
	ts := time.Date(2026, time.March, 23, 23, 30, 0, 0, time.UTC)
	got := RunFolderName("", ts)
	if !strings.HasPrefix(got, "target_") {
		t.Errorf("empty target should fall back to 'target', got %q", got)
	}
}
