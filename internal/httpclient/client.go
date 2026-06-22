// Package httpclient provides a shared, rate-limited, concurrent HTTP client
// used across all SwaggerVu modules.
package httpclient

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

func parseProxy(s string) (*url.URL, error) {
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	return url.Parse(s)
}

// userAgents is a small rotation pool used when --randomize-user-agent is set.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
}

// Options configures a Client.
type Options struct {
	Timeout        time.Duration
	Insecure       bool
	Proxy          string // http(s):// proxy URL
	UserAgent      string
	RandomizeUA    bool
	RatePerSecond  float64 // 0 = unlimited
	Headers        map[string]string
	FollowRedirect bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:        15 * time.Second,
		UserAgent:      "SwaggerVu",
		RatePerSecond:  30,
		Headers:        map[string]string{},
		FollowRedirect: false,
	}
}

// Client is a thin wrapper around http.Client adding a global rate limiter.
type Client struct {
	hc      *http.Client
	limiter *rate.Limiter
	opts    Options
}

// New builds a Client from Options.
func New(opts Options) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.Insecure},
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
	}
	if opts.Proxy != "" {
		pu, err := parseProxy(opts.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
	}
	if !opts.FollowRedirect {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	var limiter *rate.Limiter
	if opts.RatePerSecond > 0 {
		limiter = rate.NewLimiter(rate.Limit(opts.RatePerSecond), 1)
	}
	return &Client{hc: hc, limiter: limiter, opts: opts}, nil
}

// Response is a lightweight captured response.
type Response struct {
	URL         string
	Status      int
	Body        []byte
	ContentType string
	Header      http.Header
}

// Do performs a request honoring the rate limiter and default headers.
func (c *Client) Do(ctx context.Context, method, url string, body io.Reader) (*Response, error) {
	return c.DoWithHeaders(ctx, method, url, body, nil)
}

// DoWithHeaders performs a request, applying per-request headers on top of the
// client defaults (used to send the generated Content-Type and header params).
func (c *Client) DoWithHeaders(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	ua := c.opts.UserAgent
	if c.opts.RandomizeUA {
		ua = userAgents[rand.Intn(len(userAgents))]
	}
	req.Header.Set("User-Agent", ua)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, text/html, */*")
	}
	for k, v := range c.opts.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Cap body read to 5 MB to stay memory-safe across 10k targets.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}
	return &Response{
		URL:         url,
		Status:      resp.StatusCode,
		Body:        data,
		ContentType: resp.Header.Get("Content-Type"),
		Header:      resp.Header,
	}, nil
}

// Get is a convenience wrapper for GET.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, url, nil)
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// IsJSON reports whether the content type looks like JSON.
func (r *Response) IsJSON() bool {
	return strings.Contains(strings.ToLower(r.ContentType), "json")
}
