// Package policy implements IAM compliance rules and violation detection.
package policy

import (
	"strings"

	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

// Rule is a compliance check applied to an IAM statement.
type Rule struct {
	Name     string
	Severity types.Severity
	Check    func(stmt types.Statement) (bool, string) // returns (violated, detail)
}

// DefaultRules returns the standard set of IAM compliance rules.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:     "wildcard-action",
			Severity: types.Critical,
			Check: func(s types.Statement) (bool, string) {
				if s.Effect != "Allow" {
					return false, ""
				}
				for _, action := range s.Action {
					if action == "*" {
						return true, `Action "*" grants unrestricted access to all AWS services`
					}
				}
				return false, ""
			},
		},
		{
			Name:     "wildcard-resource",
			Severity: types.High,
			Check: func(s types.Statement) (bool, string) {
				if s.Effect != "Allow" {
					return false, ""
				}
				for _, resource := range s.Resource {
					if resource == "*" {
						return true, `Resource "*" applies permissions to all resources — scope to specific ARNs`
					}
				}
				return false, ""
			},
		},
		{
			Name:     "iam-full-access",
			Severity: types.Critical,
			Check: func(s types.Statement) (bool, string) {
				if s.Effect != "Allow" {
					return false, ""
				}
				for _, action := range s.Action {
					if action == "iam:*" || action == "iam:CreateUser" ||
						action == "iam:AttachRolePolicy" || action == "iam:CreateAccessKey" {
						return true, `IAM administrative action "` + action + `" can lead to privilege escalation`
					}
				}
				return false, ""
			},
		},
		{
			Name:     "public-principal",
			Severity: types.Critical,
			Check: func(s types.Statement) (bool, string) {
				if s.Effect != "Allow" || s.Principal == nil {
					return false, ""
				}
				switch p := s.Principal.(type) {
				case string:
					if p == "*" {
						return true, `Principal "*" allows access from any AWS account or unauthenticated user`
					}
				}
				return false, ""
			},
		},
		{
			Name:     "notaction-overreach",
			Severity: types.High,
			Check: func(s types.Statement) (bool, string) {
				if s.Effect == "Allow" && len(s.NotAction) > 0 {
					return true, `NotAction with Allow effect grants all actions EXCEPT those listed — almost always overly broad`
				}
				return false, ""
			},
		},
		{
			Name:     "sensitive-service-no-condition",
			Severity: types.Medium,
			Check: func(s types.Statement) (bool, string) {
				if s.Effect != "Allow" || s.Condition != nil {
					return false, ""
				}
				sensitiveServices := []string{"kms:", "secretsmanager:", "sts:AssumeRole", "lambda:InvokeFunction"}
				for _, action := range s.Action {
					for _, svc := range sensitiveServices {
						if strings.HasPrefix(action, svc) || action == svc {
							return true, `Sensitive action "` + action + `" has no Condition — consider MFA or IP condition`
						}
					}
				}
				return false, ""
			},
		},
	}
}
