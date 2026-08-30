package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

// Validator scans IAM policies for compliance violations.
type Validator struct {
	rules []Rule
}

// New returns a Validator with the default rule set.
func New() *Validator {
	return &Validator{rules: DefaultRules()}
}

// NewWithRules returns a Validator with a custom rule set.
func NewWithRules(rules []Rule) *Validator {
	return &Validator{rules: rules}
}

// ScanPolicy runs all rules against every statement in a policy.
func (v *Validator) ScanPolicy(policy types.Policy) types.ScanResult {
	result := types.ScanResult{PolicyName: policy.Name}

	for _, stmt := range policy.Statements {
		for _, rule := range v.rules {
			violated, detail := rule.Check(stmt)
			if violated {
				result.Violations = append(result.Violations, types.Violation{
					PolicyName:   policy.Name,
					StatementSid: stmt.Sid,
					Rule:         rule.Name,
					Severity:     rule.Severity,
					Detail:       detail,
				})
			}
		}
	}

	result.Compliant = len(result.Violations) == 0
	return result
}

// ScanFile parses a JSON policy file and scans it.
func (v *Validator) ScanFile(path string) (types.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var policy types.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return types.ScanResult{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if policy.Name == "" {
		policy.Name = path
	}
	return v.ScanPolicy(policy), nil
}

// ScanFiles scans multiple policy files concurrently.
func (v *Validator) ScanFiles(paths []string) types.SummaryReport {
	results := make([]types.ScanResult, len(paths))
	var wg sync.WaitGroup

	for i, path := range paths {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			result, err := v.ScanFile(p)
			if err != nil {
				result = types.ScanResult{
					PolicyName: p,
					Violations: []types.Violation{{
						PolicyName: p,
						Rule:       "parse-error",
						Severity:   types.High,
						Detail:     err.Error(),
					}},
				}
			}
			results[idx] = result
		}(i, path)
	}
	wg.Wait()

	return buildReport(results)
}

// ScanPolicies scans multiple in-memory policies concurrently.
func (v *Validator) ScanPolicies(policies []types.Policy) types.SummaryReport {
	results := make([]types.ScanResult, len(policies))
	var wg sync.WaitGroup

	for i, policy := range policies {
		wg.Add(1)
		go func(idx int, p types.Policy) {
			defer wg.Done()
			results[idx] = v.ScanPolicy(p)
		}(i, policy)
	}
	wg.Wait()

	return buildReport(results)
}

func buildReport(results []types.ScanResult) types.SummaryReport {
	report := types.SummaryReport{
		TotalPolicies: len(results),
		Results:       results,
	}
	for _, r := range results {
		if r.Compliant {
			report.CompliantCount++
		}
		report.ViolationCount += len(r.Violations)
		for _, v := range r.Violations {
			switch v.Severity {
			case types.Critical:
				report.CriticalCount++
			case types.High:
				report.HighCount++
			}
		}
	}
	return report
}
