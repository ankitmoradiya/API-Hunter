// apihunter/internal/auth/auth.go
package auth

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	httpclient "github.com/apihunter/apihunter/internal/http"
)

// AuthType represents the type of authentication
type AuthType string

const (
	AuthTypeForm  AuthType = "form"  // HTML form POST (application/x-www-form-urlencoded)
	AuthTypeJSON  AuthType = "json"  // JSON API POST (application/json)
	AuthTypeBasic AuthType = "basic" // HTTP Basic Auth
)

// Config holds authentication configuration
type Config struct {
	LoginURL      string   // URL to POST login credentials
	Username      string   // Username/email
	Password      string   // Password
	AuthType      AuthType // Type of authentication
	UsernameField string   // Form field name for username (default: "username")
	PasswordField string   // Form field name for password (default: "password")
	ExtraFields   map[string]string // Additional form fields (e.g., CSRF token)
}

// Result holds the authentication result
type Result struct {
	Success     bool
	Cookies     string            // Session cookies to use
	Headers     map[string]string // Headers to set (e.g., Authorization)
	Token       string            // Extracted token (if found)
	Message     string            // Success/error message
}

// Authenticator handles automatic login
type Authenticator struct {
	client *httpclient.Client
	config *Config
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(client *httpclient.Client, config *Config) *Authenticator {
	// Set defaults
	if config.UsernameField == "" {
		config.UsernameField = "username"
	}
	if config.PasswordField == "" {
		config.PasswordField = "password"
	}
	if config.AuthType == "" {
		config.AuthType = AuthTypeForm
	}

	return &Authenticator{
		client: client,
		config: config,
	}
}

// Login performs automatic login and returns the result
func (a *Authenticator) Login() (*Result, error) {
	switch a.config.AuthType {
	case AuthTypeForm:
		return a.loginForm()
	case AuthTypeJSON:
		return a.loginJSON()
	case AuthTypeBasic:
		return a.loginBasic()
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", a.config.AuthType)
	}
}

// loginForm performs form-based login
func (a *Authenticator) loginForm() (*Result, error) {
	formData := map[string]string{
		a.config.UsernameField: a.config.Username,
		a.config.PasswordField: a.config.Password,
	}

	// Add extra fields if any
	for k, v := range a.config.ExtraFields {
		formData[k] = v
	}

	body, status, headers, err := a.client.PostForm(a.config.LoginURL, formData)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Login request failed: %v", err),
		}, err
	}

	return a.processLoginResponse(body, status, headers)
}

// loginJSON performs JSON API login
func (a *Authenticator) loginJSON() (*Result, error) {
	loginData := map[string]string{
		a.config.UsernameField: a.config.Username,
		a.config.PasswordField: a.config.Password,
	}

	// Add extra fields if any
	for k, v := range a.config.ExtraFields {
		loginData[k] = v
	}

	jsonBody, err := json.Marshal(loginData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login data: %v", err)
	}

	body, status, headers, err := a.client.PostJSON(a.config.LoginURL, jsonBody)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Login request failed: %v", err),
		}, err
	}

	return a.processLoginResponse(body, status, headers)
}

// loginBasic sets up HTTP Basic authentication
func (a *Authenticator) loginBasic() (*Result, error) {
	// For basic auth, we just need to set the Authorization header
	// No actual login request needed
	return &Result{
		Success: true,
		Headers: map[string]string{
			"Authorization": "Basic " + basicAuth(a.config.Username, a.config.Password),
		},
		Message: "Basic auth configured",
	}, nil
}

// processLoginResponse processes the login response and extracts auth data
func (a *Authenticator) processLoginResponse(body []byte, status int, headers map[string]string) (*Result, error) {
	result := &Result{
		Headers: make(map[string]string),
	}

	// Check for Set-Cookie header
	if cookies, ok := headers["Set-Cookie"]; ok && cookies != "" {
		result.Cookies = cookies
		result.Success = true
	}

	// Try to extract token from JSON response
	token := extractToken(body)
	if token != "" {
		result.Token = token
		result.Headers["Authorization"] = "Bearer " + token
		result.Success = true
	}

	// Check status code
	if status >= 200 && status < 400 {
		if result.Cookies != "" || result.Token != "" {
			result.Success = true
			result.Message = fmt.Sprintf("Login successful (status: %d)", status)
		} else {
			// Success status but no cookies/token - might still be OK
			result.Success = true
			result.Message = fmt.Sprintf("Login completed (status: %d) - no session cookies or tokens found in response", status)
		}
	} else if status == 401 || status == 403 {
		result.Success = false
		result.Message = fmt.Sprintf("Login failed: unauthorized (status: %d)", status)
	} else if status >= 400 {
		result.Success = false
		result.Message = fmt.Sprintf("Login failed (status: %d)", status)
	}

	return result, nil
}

// extractToken tries to extract auth token from JSON response
func extractToken(body []byte) string {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	// Common token field names
	tokenFields := []string{
		"token",
		"access_token",
		"accessToken",
		"auth_token",
		"authToken",
		"jwt",
		"id_token",
		"idToken",
		"session_token",
		"sessionToken",
		"bearer",
	}

	// Check top-level fields
	for _, field := range tokenFields {
		if token, ok := data[field].(string); ok && token != "" {
			return token
		}
	}

	// Check nested in common structures
	nestedPaths := [][]string{
		{"data", "token"},
		{"data", "access_token"},
		{"data", "accessToken"},
		{"result", "token"},
		{"response", "token"},
		{"auth", "token"},
		{"user", "token"},
	}

	for _, path := range nestedPaths {
		if token := getNestedString(data, path); token != "" {
			return token
		}
	}

	// Try regex for JWT pattern in response body
	jwtRegex := regexp.MustCompile(`"(?:token|access_token|accessToken|jwt|bearer)":\s*"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"`)
	if matches := jwtRegex.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

// getNestedString gets a string value from nested map
func getNestedString(data map[string]interface{}, path []string) string {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return ""
		}
	}
	return ""
}

// basicAuth encodes username:password for Basic auth
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64Encode(auth)
}

// base64Encode encodes string to base64
func base64Encode(s string) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder

	for i := 0; i < len(s); i += 3 {
		var n uint32
		var padding int

		n = uint32(s[i]) << 16
		if i+1 < len(s) {
			n |= uint32(s[i+1]) << 8
		} else {
			padding++
		}
		if i+2 < len(s) {
			n |= uint32(s[i+2])
		} else {
			padding++
		}

		result.WriteByte(base64Chars[(n>>18)&0x3F])
		result.WriteByte(base64Chars[(n>>12)&0x3F])
		if padding < 2 {
			result.WriteByte(base64Chars[(n>>6)&0x3F])
		} else {
			result.WriteByte('=')
		}
		if padding < 1 {
			result.WriteByte(base64Chars[n&0x3F])
		} else {
			result.WriteByte('=')
		}
	}

	return result.String()
}

// FetchCSRFToken fetches a CSRF token from a page
func (a *Authenticator) FetchCSRFToken(pageURL string) (string, error) {
	body, status, err := a.client.Get(pageURL)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("failed to fetch page: status %d", status)
	}

	// Common CSRF token patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`name="_token"\s+value="([^"]+)"`),
		regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`),
		regexp.MustCompile(`name="csrfToken"\s+value="([^"]+)"`),
		regexp.MustCompile(`name="_csrf"\s+value="([^"]+)"`),
		regexp.MustCompile(`name="authenticity_token"\s+value="([^"]+)"`),
		regexp.MustCompile(`<meta\s+name="csrf-token"\s+content="([^"]+)"`),
		regexp.MustCompile(`"csrfToken":\s*"([^"]+)"`),
	}

	for _, pattern := range patterns {
		if matches := pattern.FindSubmatch(body); len(matches) > 1 {
			return string(matches[1]), nil
		}
	}

	return "", fmt.Errorf("no CSRF token found")
}
