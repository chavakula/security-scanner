package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/security-scanner/security-scanner/internal/models"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// OSVMatcher queries the OSV.dev vulnerability database.
type OSVMatcher struct {
	client *http.Client
}

// NewOSVMatcher creates a new OSV matcher.
func NewOSVMatcher() *OSVMatcher {
	return &OSVMatcher{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *OSVMatcher) Name() string { return "osv" }

// osvBatchRequest is the batch query format for OSV API.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	Severity   []osvSeverity  `json:"severity"`
	Affected   []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
	Published  time.Time      `json:"published"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ecosystemMap converts our internal ecosystem names to OSV API names.
var ecosystemMap = map[models.Ecosystem]string{
	models.EcosystemGo:    "Go",
	models.EcosystemPyPI:  "PyPI",
	models.EcosystemNpm:   "npm",
	models.EcosystemMaven: "Maven",
}

func (m *OSVMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// Build batch request — process in chunks of 1000 (OSV limit)
	var allVulns []models.Vulnerability
	chunkSize := 1000

	for i := 0; i < len(packages); i += chunkSize {
		end := i + chunkSize
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[i:end]

		vulns, err := m.queryBatch(ctx, chunk)
		if err != nil {
			return allVulns, err
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (m *OSVMatcher) queryBatch(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	batchReq := osvBatchRequest{
		Queries: make([]osvQuery, len(packages)),
	}

	for i, pkg := range packages {
		eco := ecosystemMap[pkg.Ecosystem]
		if eco == "" {
			eco = string(pkg.Ecosystem)
		}
		batchReq.Queries[i] = osvQuery{
			Package: osvPackage{
				Name:      pkg.Name,
				Ecosystem: eco,
			},
			Version: pkg.Version,
		}
	}

	body, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api returned status %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var vulns []models.Vulnerability
	for i, result := range batchResp.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]

		for _, v := range result.Vulns {
			vuln := models.Vulnerability{
				ID:          v.ID,
				Aliases:     v.Aliases,
				Summary:     v.Summary,
				Details:     v.Details,
				Severity:    parseSeverity(v.Severity),
				Package:     pkg,
				Source:      models.SourceOSV,
				PublishedAt: v.Published,
			}

			// Extract fixed version
			for _, affected := range v.Affected {
				for _, r := range affected.Ranges {
					for _, event := range r.Events {
						if event.Fixed != "" {
							vuln.FixedIn = event.Fixed
						}
					}
				}
			}

			// Extract references
			for _, ref := range v.References {
				vuln.References = append(vuln.References, ref.URL)
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

// parseSeverity converts OSV severity to our Severity type.
func parseSeverity(severities []osvSeverity) models.Severity {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			return cvssToSeverity(s.Score)
		}
	}
	return models.SeverityUnknown
}

// cvssToSeverity converts a CVSS v3 vector string to a severity level.
func cvssToSeverity(score string) models.Severity {
	// CVSS scores are in the vector string; for simplicity, map by prefix patterns
	// A proper implementation would parse the full vector
	// For now, return UNKNOWN and let the score be set from NVD or other sources
	return models.SeverityUnknown
}
