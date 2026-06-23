package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/httpclient"
	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/spf13/cobra"
)

// version is the build version. It defaults to a dev value and is overridden at
// release time via -ldflags "-X .../cmd.version=<tag>" (see .goreleaser.yaml).
var version = "1.0.0"

// Global flags shared across subcommands.
var (
	flagConcurrency int
	flagRate        float64
	flagTimeout     int
	flagInsecure    bool
	flagProxy       string
	flagUserAgent   string
	flagRandomUA    bool
	flagHeaders     []string
	flagQuiet       bool
	flagOutput      string
	flagJSON        bool
)

var log = &output.Logger{}

var rootCmd = &cobra.Command{
	Use:   "swaggervu",
	Short: "SwaggerVu — all-in-one Swagger/OpenAPI discovery, audit & testing tool",
	Long: `SwaggerVu discovers, parses, audits and (opt-in) tests Swagger/OpenAPI APIs
across many targets at once.

For authorized security testing and bug-bounty use only. You are responsible
for ensuring you have permission to test every target you supply.`,
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log.Quiet = flagQuiet
	},
}

// Execute runs the root command with a context cancelled on SIGINT/SIGTERM, so
// an interrupted run still flushes buffered output (deferred sink.Close runs).
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first interrupt cancels ctx, restore default signal handling so a
	// second Ctrl+C force-kills immediately even if some work ignores the context.
	go func() {
		<-ctx.Done()
		stop()
	}()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.IntVarP(&flagConcurrency, "concurrency", "c", 50, "number of concurrent workers")
	pf.Float64Var(&flagRate, "rate", 50, "max requests per second (0 = unlimited)")
	pf.IntVarP(&flagTimeout, "timeout", "t", 15, "request timeout in seconds")
	pf.BoolVarP(&flagInsecure, "insecure", "k", false, "skip TLS certificate verification")
	pf.StringVar(&flagProxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	pf.StringVarP(&flagUserAgent, "user-agent", "A", "SwaggerVu/"+version, "User-Agent header")
	pf.BoolVar(&flagRandomUA, "random-agent", false, "randomize the User-Agent per request")
	pf.StringSliceVarP(&flagHeaders, "header", "H", nil, "extra header 'Name: Value' (repeatable)")
	pf.BoolVarP(&flagQuiet, "quiet", "q", false, "suppress banner and status output")
	pf.StringVarP(&flagOutput, "output", "o", "", "write results to file instead of stdout")
	pf.BoolVar(&flagJSON, "json", false, "output results as JSON")
}

// buildClient constructs the shared HTTP client from global flags.
func buildClient(followRedirect bool) (*httpclient.Client, error) {
	opts := httpclient.DefaultOptions()
	opts.Timeout = time.Duration(flagTimeout) * time.Second
	opts.Insecure = flagInsecure
	opts.Proxy = flagProxy
	opts.UserAgent = flagUserAgent
	opts.RandomizeUA = flagRandomUA
	opts.RatePerSecond = flagRate
	opts.FollowRedirect = followRedirect
	opts.Headers = parseHeaders(flagHeaders)
	return httpclient.New(opts)
}

func parseHeaders(hs []string) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		if i := strings.IndexByte(h, ':'); i > 0 {
			out[strings.TrimSpace(h[:i])] = strings.TrimSpace(h[i+1:])
		}
	}
	return out
}

// readTargets gathers targets from a file, args, and/or stdin (when piped).
func readTargets(file string, args []string) ([]string, error) {
	var targets []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") || seen[s] {
			return
		}
		seen[s] = true
		targets = append(targets, s)
	}
	for _, a := range args {
		add(a)
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	// Read stdin if it's piped (not a TTY).
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	return targets, nil
}
