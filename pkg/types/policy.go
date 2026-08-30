// Package types defines shared data structures for IAM policy analysis.
package types

import "encoding/json"

// Policy represents an IAM policy document.
type Policy struct {
	Name       string      `json:"name,omitempty"`
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// Statement is a single IAM policy statement.
type Statement struct {
	Sid       string        `json:"Sid,omitempty"`
	Effect    string        `json:"Effect"`
	Principal interface{}   `json:"Principal,omitempty"`
	Action    StringOrSlice `json:"Action,omitempty"`
	NotAction StringOrSlice `json:"NotAction,omitempty"`
	Resource  StringOrSlice `json:"Resource,omitempty"`
	Condition interface{}   `json:"Condition,omitempty"`
}

// StringOrSlice unmarshals a JSON value that can be either a string or a []string.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrSlice{str}
		return nil
	}
	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*s = StringOrSlice(slice)
	return nil
}

// Severity levels for policy violations.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

// Violation describes a single compliance issue found in a policy.
type Violation struct {
	PolicyName   string   `json:"policy_name"`
	StatementSid string   `json:"statement_sid,omitempty"`
	Rule         string   `json:"rule"`
	Severity     Severity `json:"severity"`
	Detail       string   `json:"detail"`
}

// ScanResult is the output of scanning one policy.
type ScanResult struct {
	PolicyName string      `json:"policy_name"`
	Violations []Violation `json:"violations"`
	Compliant  bool        `json:"compliant"`
}

// SummaryReport aggregates results across all scanned policies.
type SummaryReport struct {
	TotalPolicies  int          `json:"total_policies"`
	CompliantCount int          `json:"compliant_count"`
	ViolationCount int          `json:"violation_count"`
	CriticalCount  int          `json:"critical_count"`
	HighCount      int          `json:"high_count"`
	Results        []ScanResult `json:"results"`
}
