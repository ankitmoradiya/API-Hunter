// apihunter/internal/http/client.go
package http

import (
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// Client is a rate-limited HTTP client
type Client struct {
	client       *fasthttp.Client
	rateLimit    int
	tokens       chan struct{}
	headers      map[string]string
	cookies      string
	mu           sync.Mutex
	maxRedirects int
}

// NewClient creates a new rate-limited HTTP client
func NewClient(rateLimit int, timeout time.Duration) *Client {
	c := &Client{
		client: &fasthttp.Client{
			ReadTimeout:     timeout,
			WriteTimeout:    timeout,
			MaxConnsPerHost: 100,
		},
		rateLimit:    rateLimit,
		tokens:       make(chan struct{}, rateLimit),
		headers:      make(map[string]string),
		maxRedirects: 10,
	}

	// Fill token bucket
	for i := 0; i < rateLimit; i++ {
		c.tokens <- struct{}{}
	}

	// Refill tokens
	go c.refillTokens()

	return c
}

func (c *Client) refillTokens() {
	ticker := time.NewTicker(time.Second / time.Duration(c.rateLimit))
	defer ticker.Stop()

	for range ticker.C {
		select {
		case c.tokens <- struct{}{}:
		default:
		}
	}
}

// SetHeader sets a default header for all requests
func (c *Client) SetHeader(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers[key] = value
}

// SetCookies sets cookies for all requests
func (c *Client) SetCookies(cookies string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cookies = cookies
}

// Get performs a rate-limited GET request with redirect following
func (c *Client) Get(url string) ([]byte, int, error) {
	<-c.tokens // Wait for rate limit token

	return c.doGet(url, 0)
}

// doGet performs the actual GET request with redirect counting
func (c *Client) doGet(url string, redirectCount int) ([]byte, int, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("GET")

	c.mu.Lock()
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.cookies != "" {
		req.Header.Set("Cookie", c.cookies)
	}
	c.mu.Unlock()

	req.Header.Set("User-Agent", "APIHunter/0.1.0")

	err := c.client.Do(req, resp)
	if err != nil {
		return nil, 0, err
	}

	statusCode := resp.StatusCode()

	// Handle redirects (301, 302, 303, 307, 308)
	if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308) && redirectCount < c.maxRedirects {
		location := string(resp.Header.Peek("Location"))
		if location != "" {
			// Handle relative URLs
			if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
				// Parse original URL to get base
				if strings.HasPrefix(location, "/") {
					// Absolute path - need to extract scheme and host
					uri := fasthttp.AcquireURI()
					uri.Parse(nil, []byte(url))
					location = string(uri.Scheme()) + "://" + string(uri.Host()) + location
					fasthttp.ReleaseURI(uri)
				} else {
					// Relative path
					lastSlash := strings.LastIndex(url, "/")
					if lastSlash > 0 {
						location = url[:lastSlash+1] + location
					}
				}
			}
			return c.doGet(location, redirectCount+1)
		}
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	return body, statusCode, nil
}

// PostForm performs a rate-limited POST request with form data
func (c *Client) PostForm(url string, formData map[string]string) ([]byte, int, map[string]string, error) {
	<-c.tokens // Wait for rate limit token

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Build form data
	args := req.PostArgs()
	for k, v := range formData {
		args.Set(k, v)
	}

	c.mu.Lock()
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.cookies != "" {
		req.Header.Set("Cookie", c.cookies)
	}
	c.mu.Unlock()

	req.Header.Set("User-Agent", "APIHunter/0.1.0")

	err := c.client.Do(req, resp)
	if err != nil {
		return nil, 0, nil, err
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	// Extract response headers
	respHeaders := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		respHeaders[string(key)] = string(value)
	})

	// Extract Set-Cookie headers specially (there can be multiple)
	var cookies []string
	resp.Header.VisitAllCookie(func(key, value []byte) {
		cookies = append(cookies, string(key)+"="+string(value))
	})
	if len(cookies) > 0 {
		respHeaders["Set-Cookie"] = strings.Join(cookies, "; ")
	}

	return body, resp.StatusCode(), respHeaders, nil
}

// PostJSON performs a rate-limited POST request with JSON body
func (c *Client) PostJSON(url string, jsonBody []byte) ([]byte, int, map[string]string, error) {
	<-c.tokens // Wait for rate limit token

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(jsonBody)

	c.mu.Lock()
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.cookies != "" {
		req.Header.Set("Cookie", c.cookies)
	}
	c.mu.Unlock()

	req.Header.Set("User-Agent", "APIHunter/0.1.0")

	err := c.client.Do(req, resp)
	if err != nil {
		return nil, 0, nil, err
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	// Extract response headers
	respHeaders := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		respHeaders[string(key)] = string(value)
	})

	// Extract Set-Cookie headers specially
	var cookies []string
	resp.Header.VisitAllCookie(func(key, value []byte) {
		cookies = append(cookies, string(key)+"="+string(value))
	})
	if len(cookies) > 0 {
		respHeaders["Set-Cookie"] = strings.Join(cookies, "; ")
	}

	return body, resp.StatusCode(), respHeaders, nil
}

// AppendCookies appends new cookies to existing ones
func (c *Client) AppendCookies(newCookies string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies == "" {
		c.cookies = newCookies
	} else {
		c.cookies = c.cookies + "; " + newCookies
	}
}

// GetCookies returns current cookies
func (c *Client) GetCookies() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cookies
}
