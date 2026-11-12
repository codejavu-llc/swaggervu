package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/httpclient"
	"github.com/codejavu-llc/swaggervu/internal/requestgen"
)

func TestCredentialedResponseLabels(t *testing.T) {
	const cookie = "review_session=artificial-review-value"
	const authorization = "Bearer artificial-review-value"
	cases := []struct {
		name           string
		clientHeaders  map[string]string
		requestHeaders map[string]string
		authHeaders    map[string]string
		protected      bool
		requiresAuth   bool
		wantStatuses   []int
		wantReasons    []string
		wantAuthStatus int
	}{
		{name: "public data", wantStatuses: []int{200}, wantReasons: []string{"unauthenticated data"}},
		{name: "ordinary header", clientHeaders: map[string]string{"Accept-Language": "en"}, wantStatuses: []int{200}, wantReasons: []string{"unauthenticated data"}},
		{name: "private refusal", protected: true, wantStatuses: []int{401}},
		{name: "global Cookie", clientHeaders: map[string]string{"Cookie": cookie}, protected: true, wantStatuses: []int{200}},
		{name: "global Authorization", clientHeaders: map[string]string{"Authorization": authorization}, protected: true, wantStatuses: []int{200}},
		{name: "operation Cookie", requestHeaders: map[string]string{"cookie": cookie}, protected: true, wantStatuses: []int{200}},
		{name: "working auth comparison", authHeaders: map[string]string{"Cookie": cookie}, protected: true, wantStatuses: []int{401, 200}, wantAuthStatus: 200},
		{name: "credentialed comparison baseline", clientHeaders: map[string]string{"Cookie": cookie}, authHeaders: map[string]string{"Cookie": cookie}, protected: true, wantStatuses: []int{200, 200}, wantAuthStatus: 200},
		{name: "credentialed required-auth baseline", clientHeaders: map[string]string{"Cookie": cookie}, authHeaders: map[string]string{"Cookie": cookie}, protected: true, requiresAuth: true, wantStatuses: []int{200, 200}, wantAuthStatus: 200},
		{name: "empty Cookie", clientHeaders: map[string]string{"Cookie": ""}, wantStatuses: []int{200}, wantReasons: []string{"unauthenticated data"}},
		{name: "operation clears Cookie", clientHeaders: map[string]string{"Cookie": cookie}, requestHeaders: map[string]string{"Cookie": ""}, wantStatuses: []int{200}, wantReasons: []string{"unauthenticated data"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var statuses []int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := http.StatusOK
				if r.Method != http.MethodGet || r.URL.Path != "/private" {
					status = http.StatusNotFound
				} else if tc.protected && r.Header.Get("Cookie") != cookie && r.Header.Get("Authorization") != authorization {
					status = http.StatusUnauthorized
				}
				mu.Lock()
				statuses = append(statuses, status)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = w.Write([]byte(bigJSON("a")))
				} else {
					_, _ = w.Write([]byte(`{"message":"access refused"}`))
				}
			}))
			defer server.Close()
			opts := httpclient.DefaultOptions()
			opts.Headers = tc.clientHeaders
			opts.CredentialOrigins = []string{server.URL}
			opts.AllowedHosts = []string{"127.0.0.1"}
			opts.AllowPrivate = true
			opts.RatePerSecond = 0
			opts.MaxRequests = 2
			opts.MaxBodyBytes = 1024
			opts.Timeout = 2 * time.Second
			client, err := httpclient.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var results []Result
			fire(ctx, client, []requestgen.Request{{
				Method: http.MethodGet, URL: server.URL + "/private", Path: "/private",
				Headers: tc.requestHeaders, RequiresAuth: tc.requiresAuth,
			}}, Config{Concurrency: 1, EmitAll: true, AuthHeaders: tc.authHeaders}, func(r Result) {
				results = append(results, r)
			})
			mu.Lock()
			gotStatuses := append([]int(nil), statuses...)
			mu.Unlock()
			if !reflect.DeepEqual(gotStatuses, tc.wantStatuses) {
				t.Fatalf("received request statuses = %v, want %v", gotStatuses, tc.wantStatuses)
			}
			if len(results) != 1 {
				t.Fatalf("got %d result rows, want one", len(results))
			}
			got := results[0]
			if got.Status != tc.wantStatuses[0] || got.AuthStatus != tc.wantAuthStatus {
				t.Errorf("result statuses = %d/%d, want %d/%d", got.Status, got.AuthStatus, tc.wantStatuses[0], tc.wantAuthStatus)
			}
			if !reflect.DeepEqual(got.Reasons, tc.wantReasons) {
				t.Errorf("reasons = %v, want %v", got.Reasons, tc.wantReasons)
			}
			if got.Interesting != (len(tc.wantReasons) > 0) {
				t.Errorf("interesting = %v, reasons = %v", got.Interesting, got.Reasons)
			}
		})
	}
}
