package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/spf13/cobra"
)

type diffReport struct {
	SchemaVersion string   `json:"schema_version"`
	Added         []string `json:"added,omitempty"`
	Removed       []string `json:"removed,omitempty"`
	Breaking      bool     `json:"breaking"`
}

var diffCmd = &cobra.Command{
	Use:   "diff <old-spec> <new-spec>",
	Short: "Show added and removed API operations between two descriptions",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldSpec, err := loadSpecFromSource(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("load old spec: %w", err)
		}
		newSpec, err := loadSpecFromSource(cmd.Context(), args[1])
		if err != nil {
			return fmt.Errorf("load new spec: %w", err)
		}
		oldSet, newSet := stringSet(detect.Endpoints(oldSpec)), stringSet(detect.Endpoints(newSpec))
		r := diffReport{SchemaVersion: "swaggervu.diff/v1"}
		for endpoint := range newSet {
			if !oldSet[endpoint] {
				r.Added = append(r.Added, endpoint)
			}
		}
		for endpoint := range oldSet {
			if !newSet[endpoint] {
				r.Removed = append(r.Removed, endpoint)
			}
		}
		sort.Strings(r.Added)
		sort.Strings(r.Removed)
		r.Breaking = len(r.Removed) > 0
		var body []byte
		if flagJSON {
			encoded, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				return err
			}
			body = append(encoded, '\n')
		} else {
			var b strings.Builder
			for _, endpoint := range r.Added {
				fmt.Fprintln(&b, "+ "+endpoint)
			}
			for _, endpoint := range r.Removed {
				fmt.Fprintln(&b, "- "+endpoint)
			}
			fmt.Fprintf(&b, "added=%d removed=%d breaking=%t\n", len(r.Added), len(r.Removed), r.Breaking)
			body = []byte(b.String())
		}
		if flagOutput != "" {
			return writePrivateFile(flagOutput, body)
		}
		fmt.Print(string(body))
		return nil
	},
}

func stringSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

func init() { rootCmd.AddCommand(diffCmd) }
