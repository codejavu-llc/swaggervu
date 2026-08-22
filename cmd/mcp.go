package cmd

import (
	"fmt"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/mcpserver"
	"github.com/spf13/cobra"
)

var (
	mcpRoots  []string
	mcpActive bool
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run the policy-bounded local MCP server over stdio",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if len(flagAllowedHosts) == 0 && len(mcpRoots) == 0 {
			return fmt.Errorf("provide at least one --allow-host or --allow-root; MCP authority is fixed at startup")
		}
		service, err := mcpserver.New(mcpserver.Config{
			Version: version, AllowedHosts: flagAllowedHosts, AllowedRoots: mcpRoots,
			AllowPrivate: flagAllowPrivate, Active: mcpActive, MaxRequests: flagMaxRequests,
			MaxBodyBytes: flagMaxBodyMB << 20, Rate: flagRate, Timeout: time.Duration(flagTimeout) * time.Second,
		})
		if err != nil {
			return err
		}
		// stdout is reserved for MCP protocol frames. All diagnostics stay on stderr.
		return service.Run(cmd.Context())
	},
}

func init() {
	f := mcpCmd.Flags()
	f.StringSliceVar(&mcpRoots, "allow-root", nil, "filesystem root containing readable specs (repeatable)")
	f.BoolVar(&mcpActive, "active", false, "enable the bounded GET/HEAD scan tool")
	rootCmd.AddCommand(mcpCmd)
}
