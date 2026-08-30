package policy

import (
	"testing"

	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

func makePolicy(name string, stmts ...types.Statement) types.Policy {
	return types.Policy{Name: name, Version: "2012-10-17", Statements: stmts}
}

func stmt(effect string, actions, resources []string) types.Statement {
	return types.Statement{
		Effect:   effect,
		Action:   types.StringOrSlice(actions),
		Resource: types.StringOrSlice(resources),
	}
}

var v = New()

func TestCompliantPolicy(t *testing.T) {
	p := makePolicy("compliant",
		stmt("Allow", []string{"s3:GetObject", "s3:PutObject"}, []string{"arn:aws:s3:::my-bucket/*"}),
	)
	result := v.ScanPolicy(p)
	if !result.Compliant {
		t.Errorf("expected compliant, got violations: %v", result.Violations)
	}
}

func TestWildcardActionDetected(t *testing.T) {
	p := makePolicy("wildcard-action",
		stmt("Allow", []string{"*"}, []string{"*"}),
	)
	result := v.ScanPolicy(p)
	if result.Compliant {
		t.Error("expected violations for wildcard action")
	}
	assertViolation(t, result, "wildcard-action", types.Critical)
}

func TestWildcardResourceDetected(t *testing.T) {
	p := makePolicy("wildcard-resource",
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
	)
	result := v.ScanPolicy(p)
	assertViolation(t, result, "wildcard-resource", types.High)
}

func TestIAMFullAccessDetected(t *testing.T) {
	p := makePolicy("iam-admin",
		stmt("Allow", []string{"iam:*"}, []string{"*"}),
	)
	result := v.ScanPolicy(p)
	assertViolation(t, result, "iam-full-access", types.Critical)
}

func TestDenyStatementNotFlagged(t *testing.T) {
	p := makePolicy("deny-all",
		stmt("Deny", []string{"*"}, []string{"*"}),
	)
	result := v.ScanPolicy(p)
	// Deny statements should not trigger Allow-based rules
	for _, v := range result.Violations {
		if v.Rule == "wildcard-action" || v.Rule == "wildcard-resource" {
			t.Errorf("Deny statement incorrectly flagged by rule: %s", v.Rule)
		}
	}
}

func TestNotActionDetected(t *testing.T) {
	p := makePolicy("notaction",
		types.Statement{
			Effect:    "Allow",
			NotAction: types.StringOrSlice([]string{"s3:GetObject"}),
			Resource:  types.StringOrSlice([]string{"*"}),
		},
	)
	result := v.ScanPolicy(p)
	assertViolation(t, result, "notaction-overreach", types.High)
}

func TestPublicPrincipalDetected(t *testing.T) {
	p := makePolicy("public-access",
		types.Statement{
			Effect:    "Allow",
			Principal: "*",
			Action:    types.StringOrSlice([]string{"s3:GetObject"}),
			Resource:  types.StringOrSlice([]string{"arn:aws:s3:::public-bucket/*"}),
		},
	)
	result := v.ScanPolicy(p)
	assertViolation(t, result, "public-principal", types.Critical)
}

func TestConcurrentScan(t *testing.T) {
	policies := make([]types.Policy, 50)
	for i := range policies {
		policies[i] = makePolicy("policy",
			stmt("Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket/*"}),
		)
	}
	report := v.ScanPolicies(policies)
	if report.TotalPolicies != 50 {
		t.Errorf("expected 50 results, got %d", report.TotalPolicies)
	}
	if report.CompliantCount != 50 {
		t.Errorf("expected 50 compliant, got %d", report.CompliantCount)
	}
}

func assertViolation(t *testing.T, result types.ScanResult, rule string, severity types.Severity) {
	t.Helper()
	for _, v := range result.Violations {
		if v.Rule == rule && v.Severity == severity {
			return
		}
	}
	t.Errorf("expected violation rule=%s severity=%s, got: %v", rule, severity, result.Violations)
}
