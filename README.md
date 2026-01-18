# APIHunter

A powerful API reconnaissance and documentation tool for security testing. Discovers API endpoints from multiple sources and generates OpenAPI/Swagger documentation, Postman collections, and security-focused reports.

## Features

- **Multi-source reconnaissance**: Wayback Machine, CommonCrawl, sitemap/robots.txt, JavaScript parsing, web crawling
- **Automatic authentication**: Form login, JSON API login, HTTP Basic Auth
- **Smart analysis**: HTTP method inference, path parameter detection, security risk tagging
- **Multiple output formats**: OpenAPI 3.0, Postman Collection, categorized URL lists, detailed reports
- **Rate limiting**: Configurable with adaptive backoff

## Installation

### From Source

Requires Go 1.20 or later.

```bash
git clone https://github.com/yourusername/apihunter.git
cd apihunter
go build -o apihunter ./cmd/apihunter
```

### Binary

Download the latest release from the releases page.

## Quick Start

```bash
# Basic scan
./apihunter scan -u https://api.example.com

# Scan with authentication (using cookies)
./apihunter scan -u https://app.example.com -c "session=abc123; token=xyz"

# Scan with automatic login
./apihunter scan -u https://app.example.com --login-url https://app.example.com/login -U admin -P password123
```

## Usage

```
apihunter scan [flags]
```

### Target Options

| Flag | Short | Description |
|------|-------|-------------|
| `--url` | `-u` | Target URL (required) |

### Authentication Options

#### Manual Authentication

| Flag | Short | Description |
|------|-------|-------------|
| `--cookie` | `-c` | Cookies to include in requests |
| `--header` | `-H` | Custom headers (can be used multiple times) |
| `--auth-bearer` | | Bearer token for Authorization header |

#### Automatic Login

| Flag | Short | Description |
|------|-------|-------------|
| `--login-url` | | URL to POST login credentials |
| `--username` | `-U` | Username/email for auto-login |
| `--password` | `-P` | Password for auto-login |
| `--auth-type` | | Authentication type: `form`, `json`, or `basic` (default: `form`) |
| `--username-field` | | Form field name for username (default: `username`) |
| `--password-field` | | Form field name for password (default: `password`) |

### Scan Options

| Flag | Short | Description |
|------|-------|-------------|
| `--passive-only` | | Only use passive reconnaissance (no active crawling) |
| `--active-only` | | Only use active reconnaissance |
| `--crawl-depth` | | Maximum crawl depth (default: 3) |

### Rate Limiting

| Flag | Short | Description |
|------|-------|-------------|
| `--rate` | `-r` | Requests per second (default: 10) |
| `--threads` | `-t` | Concurrent connections (default: 5) |
| `--delay` | | Delay between requests |
| `--adaptive` | | Enable adaptive rate limiting (default: true) |

### Output Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output directory (default: `./apihunter_output`) |
| `--format` | `-f` | Output formats: `openapi`, `postman`, `urls`, `report` |
| `--verbose` | `-v` | Verbose output |
| `--quiet` | `-q` | Minimal output |

## Examples

### Basic Scanning

```bash
# Simple scan
./apihunter scan -u https://api.example.com

# Passive only (no active crawling, just archive data)
./apihunter scan -u https://api.example.com --passive-only

# Custom output directory
./apihunter scan -u https://api.example.com -o ./my_results
```

### Authenticated Scanning

#### Using Cookies (from browser)

1. Log into the target website in your browser
2. Open Developer Tools (F12) > Application > Cookies
3. Copy the session cookie values

```bash
./apihunter scan -u https://app.example.com -c "PHPSESSID=abc123; auth_token=xyz789"
```

#### Using Bearer Token

```bash
./apihunter scan -u https://api.example.com --auth-bearer "eyJhbGciOiJIUzI1NiIs..."
```

#### Using Custom Headers

```bash
./apihunter scan -u https://api.example.com -H "Authorization: Basic dXNlcjpwYXNz" -H "X-API-Key: my-key"
```

### Automatic Login

#### Form-based Login (HTML forms)

Most common for traditional web applications:

```bash
./apihunter scan -u https://app.example.com \
  --login-url https://app.example.com/login \
  -U admin \
  -P password123
```

With custom form field names:

```bash
./apihunter scan -u https://app.example.com \
  --login-url https://app.example.com/login \
  -U user@email.com \
  -P mypassword \
  --username-field email \
  --password-field pwd
```

#### JSON API Login (REST APIs)

For applications with JSON-based authentication:

```bash
./apihunter scan -u https://api.example.com \
  --login-url https://api.example.com/auth/login \
  -U user@email.com \
  -P password123 \
  --auth-type json
```

The tool automatically extracts JWT/Bearer tokens from common response fields:
- `token`, `access_token`, `accessToken`
- `auth_token`, `jwt`, `id_token`
- Nested: `data.token`, `response.token`, etc.

#### HTTP Basic Auth

```bash
./apihunter scan -u https://api.example.com \
  -U admin \
  -P password \
  --auth-type basic
```

### Rate Limiting

```bash
# Slower scan (2 requests/second)
./apihunter scan -u https://api.example.com -r 2

# Faster scan with more threads
./apihunter scan -u https://api.example.com -r 20 -t 10

# Add delay between requests
./apihunter scan -u https://api.example.com --delay 500ms
```

## Output Files

After scanning, the output directory contains:

| File | Description |
|------|-------------|
| `openapi.yaml` | OpenAPI 3.0 specification (Swagger) |
| `postman_collection.json` | Postman Collection v2.1 |
| `urls.txt` | All discovered URLs |
| `urls_by_risk.txt` | URLs categorized by security risk level |
| `report.md` | Human-readable markdown report |
| `results.json` | Complete scan results in JSON format |

### OpenAPI/Swagger

The generated `openapi.yaml` can be:
- Imported into Swagger UI for interactive documentation
- Used with API testing tools
- Imported into Postman, Insomnia, etc.

### Risk Categories

Endpoints are tagged by security risk:

| Risk Level | Description |
|------------|-------------|
| **Critical** | Authentication, admin, sensitive data endpoints |
| **High** | User data, payments, file operations |
| **Medium** | Standard CRUD operations |
| **Low** | Public/static content |

## Reconnaissance Modules

| Module | Type | Description |
|--------|------|-------------|
| Wayback Machine | Passive | Historical URLs from web.archive.org |
| CommonCrawl | Passive | URLs from CommonCrawl index |
| Sitemap | Active | Parses sitemap.xml and robots.txt |
| Crawler | Active | Crawls website for links and forms |
| JS Parser | Active | Extracts API endpoints from JavaScript files |

## How to Get Authentication Tokens

### From Browser Developer Tools

1. **Cookies**: F12 > Application > Cookies > Copy values
2. **Bearer Token**: F12 > Network > Click request > Headers > Authorization
3. **localStorage**: F12 > Console > `localStorage.getItem('token')`

### Copy as cURL

1. F12 > Network tab
2. Perform an action on the logged-in site
3. Right-click request > Copy > Copy as cURL
4. Extract cookies and headers from the cURL command

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any target. The authors are not responsible for misuse of this tool.
