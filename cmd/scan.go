package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/security-scanner/security-scanner/internal/models"
	"github.com/security-scanner/security-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

var scanOpts models.ScanOptions

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for security vulnerabilities",
	Long: `Scan a project directory for security vulnerabilities.

This command performs two types of analysis:
  - Dependency scanning: checks your lock files against CVE databases (OSV, NVD, GitHub Advisory)
  - AI code analysis: uses OpenAI GPT-4 to detect OWASP Top 10 patterns in source code

Use --skip-ai to run dependency scanning only (no API key required).
Use --skip-deps to run AI analysis only.`,
	Example: `  # Scan current directory
  security-scanner scan

  # Scan a specific project
  security-scanner scan /path/to/project

  # Output as JSON
  security-scanner scan --format json

  # Output as SARIF
  security-scanner scan --format sarif --output results.sarif

  # Dependencies only (no OpenAI key needed)
  security-scanner scan --skip-ai

  # Only report high and critical vulnerabilities
  security-scanner scan --severity high`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOpts.Format, "format", "f", "table", "output format: table, json, sarif")
	scanCmd.Flags().StringVarP(&scanOpts.OutputFile, "output", "o", "", "write output to file (default: stdout)")
	scanCmd.Flags().StringVarP((*string)(&scanOpts.SeverityFilter), "severity", "s", "", "minimum severity to report: critical, high, medium, low")
	scanCmd.Flags().BoolVar(&scanOpts.SkipAI, "skip-ai", false, "skip AI-powered code analysis")
	scanCmd.Flags().BoolVar(&scanOpts.SkipDeps, "skip-deps", false, "skip dependency vulnerability scanning")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine scan path
	if len(args) > 0 {
		scanOpts.Path = args[0]
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine current directory: %w", err)
		}
		scanOpts.Path = cwd
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(scanOpts.Path)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}
	scanOpts.Path = absPath
	scanOpts.Verbose = verbose

	// Validate path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %s", absPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}

	// Run the scanner
	s, err := scanner.New(scanOpts)
	if err != nil {
		return err
	}

	return s.Run(cmd.Context())
}
