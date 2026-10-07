<div align="center">
  <img src="https://github.com/ankitmoradiya/API-Hunter/blob/main/assets/logo2.png" alt="API-Hunter Logo" width="250"/>


  <!-- Badges Section: Critical for SEO and trust -->
  <p1><strong>A powerful API reconnaissance and documentation tool for security testing.</strong></p1>   <!-- Fixed Badges Section -->   <p>
    <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
    <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/Security-Recon-vibrantgreen?style=for-the-badge" alt="Focus">
    <a href="https://github.com/ankitmoradiya/API-Hunter/stargazers">
      <img src="https://img.shields.io/github/stars/ankitmoradiya/API-Hunter?style=for-the-badge&color=yellow&logo=github" alt="GitHub Stars">
    </a>
  </p>
</div>

---

## 🎯 Overview

API-Hunter is a high-performance, security-focused tool written in Go for discovering and documenting API endpoints. It is designed to assist penetration testers, bug bounty hunters, and security researchers in mapping out the attack surface of modern web applications.

It goes beyond simple crawling by leveraging multiple passive and active reconnaissance sources to find endpoints that traditional scanners often miss, and then automatically generates industry-standard documentation for further analysis.

## ✨ Key Features

| Feature | Description | Benefit for Security Testing |
| :--- | :--- | :--- |
| 🔍 **Multi-Source Recon** | Discovers endpoints from **Wayback Machine**, **CommonCrawl**, sitemaps, HTML crawling, and by parsing **JavaScript** files. | Finds hidden, deprecated, or forgotten endpoints that may contain vulnerabilities. |
| 🧩 **SPA / Bundle Parsing** | Deep-parses JavaScript bundles from single-page apps (Angular/React/Vue) where calls are built by concatenating a base URL (e.g. `apiUrl+"Controller/Action"`), and auto-discovers the API host even when it differs from the site. | Recovers the real API surface of modern SPAs that literal-only scanners miss entirely. |
| 🛡️ **Smart Analysis & Tagging** | Infers HTTP methods (including PascalCase action verbs like `Get`/`Create`/`Update`/`Delete`), detects path parameters, and tags endpoints with security risk levels (Critical, High, Medium, Low). | Prioritizes testing efforts on the most sensitive and high-risk endpoints. |
| 🔑 **Automatic Authentication** | Supports **Form Login**, **JSON API Login**, and **HTTP Basic Auth** to scan authenticated areas. | Allows comprehensive scanning of private or logged-in sections of an application. |
| 🚦 **Access-Control Check** | After discovery, re-requests every endpoint **with no session** (read-safe, `GET` only) and reports which respond **without authentication**. | Surfaces broken access control / missing auth gates automatically, no separate step. |
| 🕵️ **Secret Scanning** | Scans discovered **JavaScript bundles** (and the target page) for leaked **API keys, tokens, private keys, JWTs, and DB connection strings**. | Flags credentials exposed in public JS that could impact the organization if disclosed. |
| 📄 **Auto-Documentation** | Generates industry-standard **OpenAPI 3.0 (Swagger)** and **Postman Collection** files. | Streamlines the documentation and import process into other testing tools like Burp Suite or Postman. |
| ⚙️ **Rate Limiting** | Configurable rate limiting with adaptive backoff to avoid detection and server overload. | Ensures a stealthy and reliable scan without causing service disruption. |

## 🚀 Installation

API-Hunter requires **Go 1.24 or later**.

### From Source

```bash
# Clone the repository
git clone https://github.com/ankitmoradiya/API-Hunter.git
cd API-Hunter

# Build the binary
go build -o apihunter.exe ./cmd/apihunter (For Windows)
go build -o apihunter ./cmd/apihunter (For Linux)

# Run the tool
./apihunter.exe --help
```

### Binary (Recommended)

Download the latest pre-compiled binary for your operating system from the [**Releases** page](https://github.com/ankitmoradiya/API-Hunter/releases).

## 💡 Quick Start & Usage

### Basic Scan

```bash
# Simple scan of a target API
./apihunter.exe scan -u https://api.example.com
```

### Authenticated Scan (Form Login)

```bash
# Scan a target that requires login
./apihunter.exe scan -u https://app.example.com \
  --login-url https://app.example.com/login \
  -U admin \
  -P password123
```

### Output Formats

Each scan writes to its **own timestamped folder** so previous results are never overwritten. The `-o/--output` value is treated as a **base directory** (default: `./apihunter_output`); inside it, every run creates a folder named `<host>_<DD-Mon-YYYY>_<HH-MMAM/PM>`, e.g.:

```
apihunter_output/
└── xyz.abc.com_23-Mar-2026_11-30PM/
    ├── openapi.yaml
    ├── report.md
    ├── authtest_report.md
    └── secrets_report.md
```

> Note: a colon (`:`) is illegal in Windows paths, so the time uses a hyphen (`11-30PM`). Two scans of the same host in the same minute get a `_2`, `_3`, … suffix.

| File Name | Format | Description |
| :--- | :--- | :--- |
| `openapi.yaml` | OpenAPI 3.0 | Importable into Swagger UI, Insomnia, etc. |
| `postman_collection.json` | Postman Collection v2.1 | Ready-to-use collection for Postman. |
| `report.md` | Markdown | Human-readable report with risk categorization. |
| `results.json` | JSON | Full machine-readable results (endpoints, methods, risk, source, per-module stats). |
| `urls_all.txt` | Plain Text | All discovered endpoint URLs. |
| `urls_critical.txt` / `urls_high.txt` | Plain Text | URLs filtered by risk level (written when non-empty). |
| `urls_api.txt` / `urls_js.txt` | Plain Text | API endpoints and discovered JavaScript files. |
| `authtest_report.md` / `authtest_results.json` | Markdown / JSON | Access-control check: endpoints reachable without authentication (see below). |
| `secrets_report.md` / `secrets_results.json` | Markdown / JSON | Secrets detected in discovered JavaScript (see below). |

### Access-control & secret scanning

Both run **automatically** after each scan and write into the run folder:

- **`--auth-check`** (default **on**): read-safe unauthenticated `GET` probe of every discovered endpoint, classifying each as `EXPOSED (2xx)`, `PROTECTED`, `REACHED (4xx noauth)`, etc. Disable with `--auth-check=false`.
- **`--scan-secrets`** (default **on**): fetches discovered JS bundles and the target page and matches a battery of patterns (AWS/Google/Stripe/Slack/GitHub keys, JWTs, private keys, DB connection strings, and generic high-entropy secret assignments), filtering obvious placeholders. Disable with `--scan-secrets=false`. Full secret values are written to the report, so **treat `secrets_report.md` as sensitive**.

## 🔓 Access-Control Probe (`tools/authprobe`)

> This check now runs **automatically** during `scan` (see `--auth-check` above). The standalone `authprobe` tool remains available for re-running the probe against an existing `results.json` without re-scanning.

After a scan, verify whether the discovered endpoints actually **enforce authentication**. `authprobe` reads a scan's `results.json` and re-requests each endpoint **with no session** (no `Authorization` header, no cookies), reporting which are protected (`401/403` or a redirect to sign-in) and which respond without auth.

It is **read-safe by design**: it probes with `GET`/`OPTIONS` only and never invokes a write handler, so it cannot create, modify, or delete data.

```bash
# Run a scan first, then probe its results
go run ./tools/authprobe -in apihunter_output/results.json -out apihunter_output/authtest
```

Output: `authtest_report.md` (endpoints ranked exposed → protected, with risk level) and `authtest_results.json`. A `GET` cannot confirm the auth posture of a write-only (`POST`/`PUT`/`DELETE`) route — those are reported as `METHOD-NOT-ALLOWED` and require a method-accurate follow-up.

> ⚠️ Only run `authprobe` against systems you are authorized to test.

## 🤝 Contributing

We welcome contributions from the community! Whether it's a bug report, a new feature, or a documentation improvement, your help is appreciated.

1.  **Fork** the repository.
2.  **Clone** your fork.
3.  Create a new **branch** for your feature or fix.
4.  Make your changes and ensure tests pass.
5.  **Commit** your changes with a clear message.
6.  **Push** to your branch.
7.  Open a **Pull Request** to the `main` branch of the original repository.

Please see the `CONTRIBUTING.md` file (to be created) for detailed guidelines.

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always obtain explicit permission from the target owner before scanning any system. The authors are not responsible for any misuse of this tool.
