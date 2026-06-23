package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/codejavu-llc/swaggervu/internal/secrets"
	"github.com/spf13/cobra"
)

func marshalRaw(m map[string]any) ([]byte, error) { return json.Marshal(m) }

var secretsURL string

var secretsCmd = &cobra.Command{
	Use:   "secrets [url|file]",
	Short: "Scan an API definition for leaked credentials and secrets",
	RunE: func(cmd *cobra.Command, args []string) error {
		src := secretsURL
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
		sink, err := output.NewSink(flagOutput, flagJSON)
		if err != nil {
			return err
		}
		defer sink.Close()

		// Scan the raw spec text plus all endpoint descriptions/titles.
		var corpus string
		corpus += s.Title + "\n"
		for _, e := range detect.Endpoints(s) {
			corpus += e + "\n"
		}
		if b, err := marshalRaw(s.Raw); err == nil {
			corpus += string(b)
		}

		findings := secrets.Scan(corpus)
		for _, f := range findings {
			log.Good("%s: %s", f.Type, f.Match)
			if flagJSON {
				sink.Add(f)
			} else {
				sink.WriteLine(fmt.Sprintf("%s\t%s", f.Type, f.Match))
			}
		}
		log.Info("secrets scan complete: %d finding(s)", len(findings))
		return nil
	},
}

func init() {
	secretsCmd.Flags().StringVarP(&secretsURL, "url", "u", "", "URL or file of the API definition")
	rootCmd.AddCommand(secretsCmd)
}
