package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the local SwaggerVu installation and optional browser support",
	RunE: func(*cobra.Command, []string) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		fmt.Printf("SwaggerVu: %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Binary:    %s\n", exe)
		for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
			if path, err := exec.LookPath(name); err == nil {
				fmt.Printf("Browser:   %s\n", path)
				return nil
			}
		}
		fmt.Println("Browser:   not found (only 'verify' and JS-rendered UI fallback need Chromium/Chrome)")
		return nil
	},
}

func init() { rootCmd.AddCommand(doctorCmd) }
