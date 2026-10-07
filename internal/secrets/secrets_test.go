package secrets

import "testing"

func findingsByRule(fs []Finding) map[string]Finding {
	m := make(map[string]Finding)
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestScanContentDetectsRealSecrets(t *testing.T) {
	// Fixtures are assembled from split literals so no complete secret pattern
	// exists verbatim in source — this keeps GitHub push protection (and other
	// secret scanners) from flagging these dummy test values, while the scanner
	// still sees the full, concatenated token in `content`.
	aws := "AKIA" + "Z8RQK5TPMW9XYB3C"
	google := "AIza" + "SyB7kQ2pZ9mXrT4vNwLcEdFgHjKuPoRsQtV"
	stripe := "sk_" + "live_" + "9mXrT4vNwLcEdFgHjKuPoRsQt"
	content := `
const config = {
  awsKey: "` + aws + `",
  googleKey: "` + google + `",
  stripe: "` + stripe + `",
  mongo: "mongodb+srv://admin:S3cretP@ss@cluster0.mongodb.net/db",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtWHJUNHZOIn0.9mXrT4vNwLcEdFgHjKuP",
  apiToken: "x7Kp9mQ2vL8nR4tW1zY6",
};
-----BEGIN RSA PRIVATE KEY-----
`
	fs := scanContent("https://x/app.js", content)
	byRule := findingsByRule(fs)

	for _, want := range []string{
		"AWS Access Key ID",
		"Google API Key",
		"Stripe Live Secret Key",
		"MongoDB URI (with creds)",
		"JSON Web Token (JWT)",
		"Private Key (PEM)",
	} {
		if _, ok := byRule[want]; !ok {
			t.Errorf("expected to detect %q, but did not. found: %v", want, keys(byRule))
		}
	}
}

func TestScanContentFiltersPlaceholders(t *testing.T) {
	content := `
  apiKey: "YOUR_API_KEY_HERE",
  password: "changeme",
  token: "xxxxxxxxxxxxxxxx",
  secret: "example_secret_value",
  key: "aaaaaaaaaaaaaaaa",
`
	fs := scanContent("https://x/app.js", content)
	if len(fs) != 0 {
		t.Errorf("expected placeholders to be filtered, got %d findings: %+v", len(fs), fs)
	}
}

func TestLooksLikeSecret(t *testing.T) {
	if looksLikeSecret("password") { // dictionary word, low entropy
		t.Error("plain word should not look like a secret")
	}
	if looksLikeSecret("src/components/App") { // path
		t.Error("path should not look like a secret")
	}
	if !looksLikeSecret("x7Kp9mQ2vL8nR4tW1zY6") { // high-entropy mixed token
		t.Error("high-entropy token should look like a secret")
	}
}

func keys(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
