// Package httpclient provides a shared, rate-limited, concurrent HTTP client
// used across all SwaggerVu modules.
package httpclient

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
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
	Timeout           time.Duration
	Insecure          bool
	Proxy             string // http(s):// proxy URL
	UserAgent         string
	RandomizeUA       bool
	RatePerSecond     float64 // 0 = unlimited
	Headers           map[string]string
	FollowRedirect    bool
	AllowedHosts      []string
	AllowPrivate      bool
	MaxRequests       int64 // 0 = unlimited
	MaxBodyBytes      int64
	CredentialOrigins []string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:        15 * time.Second,
		UserAgent:      "SwaggerVu",
		RatePerSecond:  30,
		Headers:        map[string]string{},
		FollowRedirect: false,
		MaxBodyBytes:   5 << 20,
	}
}

// Client is a thin wrapper around http.Client adding a global rate limiter.
type Client struct {
	hc       *http.Client
	limiter  *rate.Limiter
	opts     Options
	policy   networkPolicy
	requests atomic.Int64
}

var ErrRequestBudget = errors.New("request budget exhausted")

// New builds a Client from Options.
func New(opts Options) (*Client, error) {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 5 << 20
	}
	origins, err := NormalizeCredentialOrigins(opts.CredentialOrigins)
	if err != nil {
		return nil, err
	}
	opts.CredentialOrigins = origins
	policy, err := newNetworkPolicy(opts.AllowedHosts, opts.AllowPrivate)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.Insecure}, // #nosec G402 -- explicit operator opt-in
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
	}
	if opts.Proxy == "" {
		dialer := &net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second}
		tr.DialContext = policy.dialContext(dialer)
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
	} else {
		hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("redirect limit exceeded")
			}
			if err := policy.validateURL(req.Context(), req.URL); err != nil {
				return err
			}
			if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
				return fmt.Errorf("cross-origin redirect denied: %s", req.URL.Redacted())
			}
			return nil
		}
	}
	var limiter *rate.Limiter
	if opts.RatePerSecond > 0 {
		limiter = rate.NewLimiter(rate.Limit(opts.RatePerSecond), 1)
	}
	return &Client{hc: hc, limiter: limiter, opts: opts, policy: policy}, nil
}

// Response is a lightweight captured response.
type Response struct {
	URL         string
	Status      int
	Body        []byte
	Truncated   bool
	ContentType string
	Header      http.Header
}

// Do performs a request honoring the rate limiter and default headers.
func (c *Client) Do(ctx context.Context, method, url string, body io.Reader) (*Response, error) {
	return c.DoWithHeaders(ctx, method, url, body, nil)
}

// ValidateURL applies scheme, scope, DNS, and private/special-address policy
// without sending a request. It is used before handing an initial URL to a
// component such as a browser that does not use Client's transport.
func (c *Client) ValidateURL(ctx context.Context, raw string) error {
	u, err := neturl(raw)
	if err != nil {
		return err
	}
	return c.policy.validateURL(ctx, u)
}

// DoWithHeaders performs a request, applying per-request headers on top of the
// client defaults (used to send the generated Content-Type and header params).
func (c *Client) DoWithHeaders(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*Response, error) {
	if c.opts.MaxRequests > 0 && c.requests.Add(1) > c.opts.MaxRequests {
		return nil, ErrRequestBudget
	}
	u, err := neturl(url)
	if err != nil {
		return nil, err
	}
	if err := c.policy.validateURL(ctx, u); err != nil {
		return nil, err
	}
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	ua := c.opts.UserAgent
	if c.opts.RandomizeUA {
		ua = userAgents[randomIndex(len(userAgents))]
	}
	req.Header.Set("User-Agent", ua)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, text/html, */*")
	}
	for k, v := range c.opts.Headers {
		if !isSensitiveHeader(k) || originAllowed(u, c.opts.CredentialOrigins) {
			req.Header.Set(k, v)
		}
	}
	for k, v := range headers {
		if !isSensitiveHeader(k) || originAllowed(u, c.opts.CredentialOrigins) {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Cap body read to 5 MB to stay memory-safe across 10k targets.
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	truncated := int64(len(data)) > c.opts.MaxBodyBytes
	if truncated {
		data = data[:c.opts.MaxBodyBytes]
	}
	return &Response{
		URL:         url,
		Status:      resp.StatusCode,
		Body:        data,
		Truncated:   truncated,
		ContentType: resp.Header.Get("Content-Type"),
		Header:      resp.Header,
	}, nil
}

func randomIndex(n int) int {
	if n <= 1 {
		return 0
	}
	value, err := crand.Int(crand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(value.Int64())
}

func neturl(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("URL must contain a host and no userinfo")
	}
	return u, nil
}

// IsSensitiveHeader reports whether a header must be bound to an exact origin.
func IsSensitiveHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key":
		return true
	}
	for _, fragment := range []string{"auth", "token", "secret", "pass", "key", "signature", "credential", "session", "cookie", "jwt"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func isSensitiveHeader(name string) bool { return IsSensitiveHeader(name) }

// NormalizeCredentialOrigins validates and canonicalizes scheme+host+port
// boundaries. Paths, queries, fragments, and userinfo are refused.
func NormalizeCredentialOrigins(origins []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(origins))
	for _, raw := range origins {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("invalid credential origin %q (expected http(s)://host[:port] only)", raw)
		}
		origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
	}
	return out, nil
}

func originAllowed(u *url.URL, origins []string) bool {
	for _, raw := range origins {
		o, err := url.Parse(raw)
		if err == nil && sameOrigin(u, o) {
			return true
		}
	}
	return false
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
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
