package cmd

import (
	"fmt"
	"strings"

	"github.com/codejavu-llc/swaggervu/internal/requestgen"
	"github.com/spf13/cobra"
)

var (
	prepURL  string
	prepTool string
	prepRisk bool
)

var prepareCmd = &cobra.Command{
	Use:   "prepare [url|file]",
	Short: "Emit ready-to-run curl/sqlmap commands for every endpoint",
	Long:  `Generate request templates per operation for manual testing in curl or sqlmap.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		src := prepURL
		if src == "" && len(args) > 0 {
			src = args[0]
		}
		if src == "" {
			return fmt.Errorf("provide a URL or file (positional arg or -u)")
		}
		log.Banner(version)

		s, err := loadSpecFromSource(cmd.Context(), src)
		if err != nil {
			return err
		}
		opts := requestgen.DefaultOptions()
		opts.IncludeRisk = prepRisk
		for _, r := range requestgen.Build(s, opts) {
			fmt.Println(commandFor(prepTool, r))
		}
		return nil
	},
}

func commandFor(tool string, r requestgen.Request) string {
	switch strings.ToLower(tool) {
	case "sqlmap":
		cmd := fmt.Sprintf("sqlmap -u '%s' --batch", r.URL)
		if r.Method != "GET" {
			cmd += " --method=" + r.Method
		}
		if r.Body != "" {
			cmd += fmt.Sprintf(" --data='%s'", r.Body)
		}
		return cmd
	default: // curl
		var b strings.Builder
		fmt.Fprintf(&b, "curl -sk -X %s '%s'", r.Method, r.URL)
		for k, v := range r.Headers {
			fmt.Fprintf(&b, " -H '%s: %s'", k, v)
		}
		if r.ContentType != "" {
			fmt.Fprintf(&b, " -H 'Content-Type: %s'", r.ContentType)
		}
		if r.Body != "" {
			fmt.Fprintf(&b, " --data '%s'", r.Body)
		}
		return b.String()
	}
}

func init() {
	f := prepareCmd.Flags()
	f.StringVarP(&prepURL, "url", "u", "", "URL or file of the API definition")
	f.StringVarP(&prepTool, "tool", "e", "curl", "external tool: curl or sqlmap")
	f.BoolVar(&prepRisk, "risk", false, "include non-GET methods (POST/PUT/PATCH/DELETE)")
	rootCmd.AddCommand(prepareCmd)
}
