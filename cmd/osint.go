package cmd

import (
	"github.com/codejavu-inc/swaggervu/internal/osint"
	"github.com/codejavu-inc/swaggervu/internal/output"
	"github.com/codejavu-inc/swaggervu/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	osintScan     bool
	osintMaxPages int
)

var osintCmd = &cobra.Command{
	Use:   "osint <search-term>",
	Short: "Discover public API definitions on SwaggerHub by domain/keyword",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		term := args[0]
		log.Banner(version)

		client, err := buildClient(true)
		if err != nil {
			return err
		}
		client2, _ := buildClient(true)

		sink, err := output.NewSink(flagOutput, flagJSON)
		if err != nil {
			return err
		}
		defer sink.Close()

		log.Info("querying SwaggerHub for '%s' (up to %d page(s))", term, osintMaxPages)
		found := 0
		total, err := osint.Search(cmd.Context(), client, term, osintMaxPages, func(sp osint.Spec) {
			found++
			log.Good("%s", sp.URL)
			if flagJSON {
				sink.Add(sp)
			} else {
				sink.WriteLine(sp.URL)
			}
			if osintScan {
				if resp, err := client2.Get(cmd.Context(), sp.URL); err == nil {
					for _, f := range secrets.Scan(resp.BodyString()) {
						log.Warn("  secret %s: %s", f.Type, f.Match)
					}
				}
			}
		})
		if err != nil {
			return err
		}
		log.Info("collected %d spec(s) (%d total match the query on SwaggerHub)", found, total)
		return nil
	},
}

func init() {
	osintCmd.Flags().BoolVar(&osintScan, "scan-secrets", false, "fetch each spec and scan it for secrets")
	osintCmd.Flags().IntVar(&osintMaxPages, "max-pages", 5, "max SwaggerHub result pages (100/page; 0 = all)")
	rootCmd.AddCommand(osintCmd)
}
