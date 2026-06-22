// Package output centralizes result formatting (console, txt, json) for SwaggerVu.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
)

// ANSI colors (disabled automatically when not a TTY).
var (
	colorEnabled = isTTY(os.Stderr)
	cReset       = "\033[0m"
	cGreen       = "\033[32m"
	cYellow      = "\033[33m"
	cRed         = "\033[31m"
	cCyan        = "\033[36m"
	cBold        = "\033[1m"
)

func colorize(c, s string) string {
	if !colorEnabled {
		return s
	}
	return c + s + cReset
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Logger writes human-readable status to stderr, keeping stdout pipe-clean.
type Logger struct {
	Quiet bool
	mu    sync.Mutex
}

func (l *Logger) line(prefix, color, format string, a ...any) {
	if l.Quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s %s\n", colorize(color, prefix), fmt.Sprintf(format, a...))
}

// Status renders an HTTP status code colored by class (when output is a TTY):
// 2xx green, 3xx cyan, 4xx yellow, 5xx red. Other codes are left uncolored.
func Status(code int) string {
	s := strconv.Itoa(code)
	switch {
	case code >= 200 && code < 300:
		return colorize(cGreen, s)
	case code >= 300 && code < 400:
		return colorize(cCyan, s)
	case code >= 400 && code < 500:
		return colorize(cYellow, s)
	case code >= 500 && code < 600:
		return colorize(cRed, s)
	default:
		return s
	}
}

func (l *Logger) Info(format string, a ...any)  { l.line("[*]", cCyan, format, a...) }
func (l *Logger) Good(format string, a ...any)  { l.line("[+]", cGreen, format, a...) }
func (l *Logger) Warn(format string, a ...any)  { l.line("[!]", cYellow, format, a...) }
func (l *Logger) Error(format string, a ...any) { l.line("[-]", cRed, format, a...) }

// Banner prints the SwaggerVu banner to stderr unless quiet.
func (l *Logger) Banner(version string) {
	if l.Quiet {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(cBold+cCyan, "  SwaggerVu")+colorize(cCyan, " — all-in-one Swagger/OpenAPI security tool ")+colorize(cReset, "v"+version))
	fmt.Fprintln(os.Stderr, colorize(cYellow, "  authorized testing only — you are responsible for your targets"))
	fmt.Fprintln(os.Stderr)
}

// Sink collects result lines and flushes them to stdout or a file.
type Sink struct {
	mu    sync.Mutex
	w     io.Writer
	close func() error
	json  bool
	items []any
}

// NewSink opens an output sink. If path is empty, writes to stdout.
func NewSink(path string, asJSON bool) (*Sink, error) {
	s := &Sink{w: os.Stdout, json: asJSON}
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		s.w = f
		s.close = f.Close
	}
	return s, nil
}

// WriteLine writes a plain text line (used in non-JSON mode).
func (s *Sink) WriteLine(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintln(s.w, line)
}

// Add stores a structured item for JSON output.
func (s *Sink) Add(item any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
}

// Close flushes JSON (if enabled) and closes the underlying file.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		enc := json.NewEncoder(s.w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(s.items); err != nil {
			return err
		}
	}
	if s.close != nil {
		return s.close()
	}
	return nil
}

// IsJSON reports whether the sink is in JSON mode.
func (s *Sink) IsJSON() bool { return s.json }
