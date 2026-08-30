package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TushGoel/iam-policy-scanner/internal/report"
	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

func sampleReport() types.SummaryReport {
	return types.SummaryReport{
		TotalPolicies:  2,
		CompliantCount: 1,
		ViolationCount: 2,
		CriticalCount:  1,
		HighCount:      1,
		Results: []types.ScanResult{
			{
				PolicyName: "policies/overpermissive.json",
				Compliant:  false,
				Violations: []types.Violation{
					{
						PolicyName: "policies/overpermissive.json",
						Rule:       "wildcard-action",
						Severity:   types.Critical,
						Detail:     "Action: * grants all AWS actions",
					},
					{
						PolicyName: "policies/overpermissive.json",
						Rule:       "wildcard-resource",
						Severity:   types.High,
						Detail:     "Resource: * applies to all resources",
					},
				},
			},
			{
				PolicyName: "policies/compliant.json",
				Compliant:  true,
			},
		},
	}
}

func TestPrintSARIF_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := report.PrintSARIF(&buf, sampleReport()); err != nil {
		t.Fatalf("PrintSARIF returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}
}

func TestPrintSARIF_SchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	_ = report.PrintSARIF(&buf, sampleReport())
	output := buf.String()
	if !strings.Contains(output, `"version": "2.1.0"`) {
		t.Error("expected SARIF version 2.1.0")
	}
}

func TestPrintSARIF_RulesDeduped(t *testing.T) {
	// Two violations with the same rule — should produce only one rule entry
	r := types.SummaryReport{
		Results: []types.ScanResult{
			{
				PolicyName: "a.json",
				Violations: []types.Violation{
					{Rule: "wildcard-action", Severity: types.Critical, Detail: "detail"},
					{Rule: "wildcard-action", Severity: types.Critical, Detail: "detail2"},
				},
			},
		},
	}
	var buf bytes.Buffer
	_ = report.PrintSARIF(&buf, r)

	var out map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &out)
	runs := out["runs"].([]interface{})
	driver := runs[0].(map[string]interface{})["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	if len(rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(rules))
	}
}

func TestPrintSARIF_SeverityMapping(t *testing.T) {
	r := types.SummaryReport{
		Results: []types.ScanResult{
			{
				PolicyName: "p.json",
				Violations: []types.Violation{
					{Rule: "r1", Severity: types.Critical, Detail: "d"},
					{Rule: "r2", Severity: types.Medium, Detail: "d"},
				},
			},
		},
	}
	var buf bytes.Buffer
	_ = report.PrintSARIF(&buf, r)
	output := buf.String()
	// Critical → error
	if !strings.Contains(output, `"level": "error"`) {
		t.Error("expected CRITICAL to map to SARIF level 'error'")
	}
	// Medium → warning
	if !strings.Contains(output, `"level": "warning"`) {
		t.Error("expected MEDIUM to map to SARIF level 'warning'")
	}
}

func TestPrintSARIF_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	err := report.PrintSARIF(&buf, types.SummaryReport{})
	if err != nil {
		t.Fatalf("PrintSARIF with empty report returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("empty report output is not valid JSON: %v", err)
	}
}
