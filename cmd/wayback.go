package cmd

import (
	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/codejavu-llc/swaggervu/internal/wayback"
	"github.com/spf13/cobra"
)

var waybackCmd = &cobra.Command{
	Use:    "wayback <domain>",
	Short:  "Harvest archived API/Swagger URLs for a domain from the Wayback Machine",
	Hidden: true, // folded into `discover --wayback`; kept as a compat alias
	Args:   cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Banner(version)
		client, err := buildClient(true)
		if err != nil {
			return err
		}
		sink, err := output.NewSink(flagOutput, flagJSON)
		if err != nil {
			return err
		}
		defer sink.Close()

		total := 0
		for _, domain := range args {
			urls, err := wayback.Fetch(cmd.Context(), client, domain)
			if err != nil {
				log.Error("wayback %s: %v", domain, err)
				continue
			}
			log.Info("%s: %d archived API URL(s)", domain, len(urls))
			for _, u := range urls {
				total++
				if flagJSON {
					sink.Add(map[string]string{"domain": domain, "url": u})
				} else {
					sink.WriteLine(u)
				}
			}
		}
		log.Info("wayback complete: %d URL(s)", total)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(waybackCmd)
}
