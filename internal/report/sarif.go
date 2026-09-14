// Package report — SARIF output for GitHub Security tab integration.
//
// SARIF (Static Analysis Results Interchange Format) is the standard format
// consumed by GitHub's Security tab, VS Code, and enterprise SAST pipelines.
// Outputting SARIF lets this scanner appear natively in GitHub PR checks.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

// SARIF 2.1.0 schema — minimum required fields for GitHub Security tab.
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

type sarifOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	FullDescription  sarifMessage     `json:"fullDescription"`
	DefaultConfig    sarifRuleConfig  `json:"defaultConfiguration"`
	HelpURI          string           `json:"helpUri,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"` // "error", "warning", "note"
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// severityToSarifLevel maps IAM scanner severity to SARIF levels.
// GitHub Security tab shows "error" as high-severity findings.
func severityToSarifLevel(s types.Severity) string {
	switch s {
	case types.Critical:
		return "error"
	case types.High:
		return "error"
	case types.Medium:
		return "warning"
	default:
		return "note"
	}
}

// uniqueRules extracts deduplicated rule definitions from all violations.
func uniqueRules(r types.SummaryReport) []sarifRule {
	seen := map[string]bool{}
	rules := []sarifRule{}
	for _, result := range r.Results {
		for _, v := range result.Violations {
			ruleID := ruleID(v.Rule)
			if seen[ruleID] {
				continue
			}
			seen[ruleID] = true
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             v.Rule,
				ShortDescription: sarifMessage{Text: v.Rule},
				FullDescription:  sarifMessage{Text: fmt.Sprintf("[%s] %s", v.Severity, v.Detail)},
				DefaultConfig:    sarifRuleConfig{Level: severityToSarifLevel(v.Severity)},
			})
		}
	}
	return rules
}

// ruleID converts a rule name to a kebab-case identifier.
func ruleID(rule string) string {
	return "IAM-" + strings.ReplaceAll(strings.ToUpper(rule), " ", "-")
}

// PrintSARIF writes SARIF 2.1.0 output to w.
// The output is suitable for upload to GitHub Code Scanning via:
//
//	gh code-scanning upload-results --sarif results.sarif
func PrintSARIF(w io.Writer, r types.SummaryReport) error {
	rules := uniqueRules(r)

	results := []sarifResult{}
	for _, scanResult := range r.Results {
		for _, v := range scanResult.Violations {
			results = append(results, sarifResult{
				RuleID: ruleID(v.Rule),
				Level:  severityToSarifLevel(v.Severity),
				Message: sarifMessage{
					Text: fmt.Sprintf("%s: %s", v.Rule, v.Detail),
				},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{
								URI: scanResult.PolicyName,
							},
							Region: sarifRegion{StartLine: 1},
						},
					},
				},
			})
		}
	}

	out := sarifOutput{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "iam-policy-scanner",
						Version:        "1.0.0",
						InformationURI: "https://github.com/TushGoel/iam-policy-scanner",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
