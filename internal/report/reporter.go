// Package report formats and prints scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

// PrintSummary writes a human-readable summary to w.
func PrintSummary(w io.Writer, r types.SummaryReport) {
	fmt.Fprintf(w, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Fprintf(w, "  IAM Policy Scan Results\n")
	fmt.Fprintf(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	fmt.Fprintf(w, "  Policies scanned:  %d\n", r.TotalPolicies)
	fmt.Fprintf(w, "  Compliant:         %d\n", r.CompliantCount)
	fmt.Fprintf(w, "  Violations found:  %d\n", r.ViolationCount)

	if r.CriticalCount > 0 {
		fmt.Fprintf(w, "  ⛔ CRITICAL:        %d\n", r.CriticalCount)
	}
	if r.HighCount > 0 {
		fmt.Fprintf(w, "  ⚠️  HIGH:           %d\n", r.HighCount)
	}

	for _, result := range r.Results {
		if result.Compliant {
			fmt.Fprintf(w, "\n  ✅ %s — no violations\n", result.PolicyName)
			continue
		}
		fmt.Fprintf(w, "\n  ❌ %s\n", result.PolicyName)
		for _, v := range result.Violations {
			sid := ""
			if v.StatementSid != "" {
				sid = fmt.Sprintf(" [%s]", v.StatementSid)
			}
			fmt.Fprintf(w, "     [%s]%s %s\n", v.Severity, sid, v.Rule)
			fmt.Fprintf(w, "       %s\n", wrap(v.Detail, 65))
		}
	}
	fmt.Fprintf(w, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// PrintJSON writes results as formatted JSON to w.
func PrintJSON(w io.Writer, r types.SummaryReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func wrap(s string, width int) string {
	if len(s) <= width {
		return s
	}
	return s[:width] + "\n         " + strings.TrimSpace(s[width:])
}
