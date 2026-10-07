package secrets

import "regexp"

// Severity levels for a secret finding.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
)

// Rule is a single secret-detection pattern.
//
// Group is the submatch index whose text is validated for placeholders/entropy
// (0 = the whole match). The full match is always what gets reported as evidence.
// Generic=true marks low-signal assignment rules that must pass the entropy/
// placeholder filter before they are kept.
type Rule struct {
	Name     string
	Severity string
	Re       *regexp.Regexp
	Group    int
	Generic  bool
}

// rules is the detection battery. High-signal vendor patterns first, then
// connection strings, then the noisy generic assignment catch-all.
var rules = []Rule{
	// --- Private keys & cloud credentials (critical) ---
	{"Private Key (PEM)", SevCritical, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), 0, false},
	{"AWS Access Key ID", SevCritical, regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b`), 1, false},
	{"AWS Secret Access Key", SevCritical, regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`), 1, false},
	{"Google Service Account Key", SevCritical, regexp.MustCompile(`"type":\s*"service_account"`), 0, false},
	{"Azure Storage Account Key", SevCritical, regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{40,})`), 1, false},

	// --- Connection strings with embedded credentials (critical) ---
	{"MongoDB URI (with creds)", SevCritical, regexp.MustCompile(`mongodb(?:\+srv)?://[^:@\s"'` + "`" + `]+:[^@\s"'` + "`" + `]+@[^\s"'` + "`" + `]+`), 0, false},
	{"DB URI (with creds)", SevCritical, regexp.MustCompile(`(?:postgres(?:ql)?|mysql|mariadb|redis|amqp|rediss)://[^:@\s"'` + "`" + `]+:[^@\s"'` + "`" + `]+@[^\s"'` + "`" + `]+`), 0, false},
	{"ADO.NET/SQL Connection String", SevCritical, regexp.MustCompile(`(?i)(?:Data Source|Server|Initial Catalog|Database)=[^"'\n]{0,200}?(?:Password|Pwd)=([^;"'\s]{3,})`), 1, false},
	{"Basic Auth in URL", SevCritical, regexp.MustCompile(`https?://[^/:@\s"'` + "`" + `]+:[^/@\s"'` + "`" + `]+@[^\s"'` + "`" + `]+`), 0, false},

	// --- Vendor API tokens (high) ---
	{"Google API Key", SevHigh, regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`), 1, false},
	{"Google OAuth Token", SevHigh, regexp.MustCompile(`\b(ya29\.[0-9A-Za-z\-_]+)`), 1, false},
	{"GitHub Token", SevHigh, regexp.MustCompile(`\b(gh[pousr]_[0-9A-Za-z]{36,})\b`), 1, false},
	{"GitLab PAT", SevHigh, regexp.MustCompile(`\b(glpat-[0-9A-Za-z\-_]{20})\b`), 1, false},
	{"Slack Token", SevHigh, regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,})\b`), 1, false},
	{"Slack Webhook", SevHigh, regexp.MustCompile(`(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)`), 1, false},
	{"Stripe Live Secret Key", SevCritical, regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`), 1, false},
	{"SendGrid API Key", SevHigh, regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`), 1, false},
	{"Twilio API Key", SevHigh, regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), 1, false},
	{"Mailgun API Key", SevHigh, regexp.MustCompile(`\b(key-[0-9a-zA-Z]{32})\b`), 1, false},
	{"npm Token", SevHigh, regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), 1, false},
	{"Square Access Token", SevHigh, regexp.MustCompile(`\b(sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43})\b`), 1, false},
	{"Firebase Cloud Messaging Key", SevHigh, regexp.MustCompile(`\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b`), 1, false},
	{"JSON Web Token (JWT)", SevHigh, regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`), 1, false},
	{"Bearer Token", SevHigh, regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9\-_=\.]{20,})`), 1, true},
	{"Authorization: Basic", SevHigh, regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']?basic\s+([A-Za-z0-9+/=]{16,})`), 1, false},

	// --- Lower-signal (medium) ---
	{"Stripe Publishable Live Key", SevMedium, regexp.MustCompile(`\b(pk_live_[0-9A-Za-z]{24,})\b`), 1, false},
	{"Generic Secret Assignment", SevMedium, regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|secret|passwd|password|pwd|token)["']?\s*[:=]\s*["']([^"'\s]{8,})["']`), 1, true},
}
