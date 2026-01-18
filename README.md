
## 🎯 Overview

API-Hunter is a high-performance, security-focused tool written in Go for discovering and documenting API endpoints. It is designed to assist penetration testers, bug bounty hunters, and security researchers in mapping out the attack surface of modern web applications.

It goes beyond simple crawling by leveraging multiple passive and active reconnaissance sources to find endpoints that traditional scanners often miss, and then automatically generates industry-standard documentation for further analysis.

## ✨ Key Features

| Feature | Description | Benefit for Security Testing |
| :--- | :--- | :--- |
| 🔍 **Multi-Source Recon** | Discovers endpoints from **Wayback Machine**, **CommonCrawl**, sitemaps, `robots.txt`, and by parsing **JavaScript** files. | Finds hidden, deprecated, or forgotten endpoints that may contain vulnerabilities. |
| 🛡️ **Smart Analysis & Tagging** | Infers HTTP methods, detects path parameters, and tags endpoints with security risk levels (Critical, High, Medium, Low). | Prioritizes testing efforts on the most sensitive and high-risk endpoints. |
| 🔑 **Automatic Authentication** | Supports **Form Login**, **JSON API Login**, and **HTTP Basic Auth** to scan authenticated areas. | Allows comprehensive scanning of private or logged-in sections of an application. |
| 📄 **Auto-Documentation** | Generates industry-standard **OpenAPI 3.0 (Swagger)** and **Postman Collection** files. | Streamlines the documentation and import process into other testing tools like Burp Suite or Postman. |
| ⚙️ **Rate Limiting** | Configurable rate limiting with adaptive backoff to avoid detection and server overload. | Ensures a stealthy and reliable scan without causing service disruption. |

## 🚀 Installation

API-Hunter requires **Go 1.20 or later**.

### From Source

```bash
# Clone the repository
git clone https://github.com/ankitmoradiya/API-Hunter.git
cd API-Hunter

# Build the binary
go build -o apihunter ./cmd/apihunter

# Run the tool
./apihunter --help
```

### Binary (Recommended)

Download the latest pre-compiled binary for your operating system from the [**Releases** page](https://github.com/ankitmoradiya/API-Hunter/releases).

## 💡 Quick Start & Usage

### Basic Scan

```bash
# Simple scan of a target API
./apihunter scan -u https://api.example.com
```

### Authenticated Scan (Form Login)

```bash
# Scan a target that requires login
./apihunter scan -u https://app.example.com \
  --login-url https://app.example.com/login \
  -U admin \
  -P password123
```

### Output Formats

The tool saves all results to a specified output directory (default: `./apihunter_output`).

| File Name | Format | Description |
| :--- | :--- | :--- |
| `openapi.yaml` | OpenAPI 3.0 | Importable into Swagger UI, Insomnia, etc. |
| `postman_collection.json` | Postman Collection v2.1 | Ready-to-use collection for Postman. |
| `urls.txt` | Plain Text | All discovered URLs. |
| `report.md` | Markdown | Human-readable report with risk categorization. |

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
