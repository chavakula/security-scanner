package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/security-scanner/security-scanner/internal/analyzer"
	"github.com/security-scanner/security-scanner/internal/config"
	"github.com/security-scanner/security-scanner/internal/detector"
	"github.com/security-scanner/security-scanner/internal/matcher"
	"github.com/security-scanner/security-scanner/internal/models"
	"github.com/security-scanner/security-scanner/internal/parser"
	"github.com/security-scanner/security-scanner/internal/reporter"
)

// Scanner orchestrates the full vulnerability scanning pipeline.
type Scanner struct {
	opts     models.ScanOptions
	cfg      *config.Config
	reporter reporter.Reporter
}

// New creates a new Scanner from the given options.
func New(opts models.ScanOptions) (*Scanner, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return &Scanner{
		opts:     opts,
		cfg:      cfg,
		reporter: reporter.ForFormat(opts.Format),
	}, nil
}

// Run executes the full scan pipeline: detect -> parse -> match -> analyze -> report.
func (s *Scanner) Run(ctx context.Context) error {
	start := time.Now()

	result := &models.ScanResult{
		ProjectPath: s.opts.Path,
		ScannedAt:   start,
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Scanning %s ...\n\n", s.opts.Path)
	}

	// Step 1: Detect ecosystems
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Detecting project ecosystems...\n")
	}

	files, ecosystems, err := detector.Detect(s.opts.Path)
	if err != nil {
		return fmt.Errorf("ecosystem detection failed: %w", err)
	}
	result.Ecosystems = ecosystems

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d manifest files across %d ecosystems\n", len(files), len(ecosystems))
		for _, f := range files {
			fmt.Fprintf(os.Stderr, "   - %s (%s)\n", f.Filename, f.Ecosystem)
		}
		fmt.Fprintln(os.Stderr)
	}

	var allVulns []models.Vulnerability

	// Step 2: Parse dependencies and match against CVE databases
	if !s.opts.SkipDeps {
		depVulns, totalPkgs, errs := s.scanDependencies(ctx, files)
		result.TotalPackages = totalPkgs
		allVulns = append(allVulns, depVulns...)
		result.Errors = append(result.Errors, errs...)
	}

	// Step 3: AI-powered source code analysis
	if !s.opts.SkipAI {
		aiVulns, errs := s.scanSourceCode(ctx)
		allVulns = append(allVulns, aiVulns...)
		result.Errors = append(result.Errors, errs...)
	}

	// Step 3.5: AI enrichment layer — enrich ALL vulnerabilities with structured analysis
	if !s.opts.SkipAI && s.cfg.OpenAIKey != "" && len(allVulns) > 0 {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Running AI enrichment on %d findings...\n", len(allVulns))
		}
		ai := analyzer.NewOpenAIAnalyzer(s.cfg.OpenAIKey, s.cfg.OpenAIModel)
		allVulns = ai.EnrichVulnerabilities(ctx, allVulns, s.opts.Verbose)
		if s.opts.Verbose {
			enriched := 0
			for _, v := range allVulns {
				if v.AIEnrichment != nil {
					enriched++
				}
			}
			fmt.Fprintf(os.Stderr, "   Enriched %d/%d findings\n\n", enriched, len(allVulns))
		}
	}

	// Step 4: Filter by severity if specified
	if s.opts.SeverityFilter != "" {
		allVulns = filterBySeverity(allVulns, s.opts.SeverityFilter)
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)

	// Step 5: Report results
	return s.writeReport(result)
}

// scanDependencies parses manifest files and queries vulnerability databases.
func (s *Scanner) scanDependencies(ctx context.Context, files []detector.DetectedFile) ([]models.Vulnerability, int, []string) {
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Parsing dependencies...\n")
	}

	// Parse all dependency files
	var allPackages []models.Package
	var errs []string

	for _, f := range files {
		p := parser.ForFile(f.Filename)
		if p == nil {
			continue
		}

		file, err := os.Open(f.Path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("cannot open %s: %v", f.Path, err))
			continue
		}

		pkgs, err := p.Parse(file, f.Path)
		file.Close()
		if err != nil {
			errs = append(errs, fmt.Sprintf("cannot parse %s: %v", f.Path, err))
			continue
		}

		allPackages = append(allPackages, pkgs...)

		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Parsed %d packages from %s\n", len(pkgs), f.Filename)
		}
	}

	if len(allPackages) == 0 {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   No packages found to scan\n\n")
		}
		return nil, 0, errs
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Total: %d packages\n\n", len(allPackages))
		fmt.Fprintf(os.Stderr, "Querying vulnerability databases...\n")
	}

	// Build matchers
	matchers := []matcher.Matcher{
		matcher.NewOSVMatcher(),
	}

	if s.cfg.NVDKey != "" {
		matchers = append(matchers, matcher.NewNVDMatcher(s.cfg.NVDKey))
	} else if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Skipping NVD (no API key configured)\n")
	}

	if s.cfg.GitHubToken != "" {
		matchers = append(matchers, matcher.NewGitHubAdvisoryMatcher(s.cfg.GitHubToken))
	} else if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Skipping GitHub Advisory (no token configured)\n")
	}

	aggregated := matcher.NewAggregatedMatcher(matchers...)
	vulns, err := aggregated.Match(ctx, allPackages)
	if err != nil {
		errs = append(errs, fmt.Sprintf("vulnerability matching error: %v", err))
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d dependency vulnerabilities\n\n", len(vulns))
	}

	return vulns, len(allPackages), errs
}

// scanSourceCode runs pattern matching and AI analysis on source files.
func (s *Scanner) scanSourceCode(ctx context.Context) ([]models.Vulnerability, []string) {
	var errs []string

	if s.cfg.OpenAIKey == "" {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Running pattern-based code analysis (no OpenAI key for AI analysis)...\n")
		}

		// Run pattern matching only
		matches, err := analyzer.ScanPatterns(s.opts.Path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("pattern scan error: %v", err))
			return nil, errs
		}

		vulns := analyzer.PatternMatchesToVulnerabilities(matches)
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Found %d potential issues via pattern matching\n\n", len(vulns))
		}

		return vulns, errs
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Running AI-powered code analysis (model: %s)...\n", s.cfg.OpenAIModel)
	}

	ai := analyzer.NewOpenAIAnalyzer(s.cfg.OpenAIKey, s.cfg.OpenAIModel)
	vulns, err := ai.Analyze(ctx, s.opts.Path, s.opts.Verbose)
	if err != nil {
		errs = append(errs, fmt.Sprintf("AI analysis error: %v", err))
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d issues via code analysis\n\n", len(vulns))
	}

	return vulns, errs
}

// writeReport sends the scan result to the appropriate output.
func (s *Scanner) writeReport(result *models.ScanResult) error {
	var w io.Writer = os.Stdout

	if s.opts.OutputFile != "" {
		f, err := os.Create(s.opts.OutputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	return s.reporter.Report(result, w)
}

// filterBySeverity filters vulnerabilities to only include those at or above the minimum severity.
func filterBySeverity(vulns []models.Vulnerability, minSeverity models.Severity) []models.Vulnerability {
	minRank := minSeverity.Rank()
	if minRank == 0 {
		// For string matching, try case-insensitive
		switch strings.ToUpper(string(minSeverity)) {
		case "CRITICAL":
			minRank = models.SeverityCritical.Rank()
		case "HIGH":
			minRank = models.SeverityHigh.Rank()
		case "MEDIUM":
			minRank = models.SeverityMedium.Rank()
		case "LOW":
			minRank = models.SeverityLow.Rank()
		default:
			return vulns
		}
	}

	var filtered []models.Vulnerability
	for _, v := range vulns {
		if v.Severity.Rank() >= minRank {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
