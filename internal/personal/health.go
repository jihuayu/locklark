package personal

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/vault"
)

const healthAction = "vault.health.local"

type HealthFinding struct {
	ID       string   `json:"id"`
	Revision string   `json:"revision"`
	Flags    []string `json:"flags"`
}
type HealthReport struct {
	Profile  string          `json:"profile"`
	Scope    string          `json:"scope"`
	Checked  int             `json:"checked"`
	Skipped  int             `json:"skipped"`
	Findings []HealthFinding `json:"findings"`
}
type HealthReceipt struct {
	Status       string       `json:"status"`
	Session      string       `json:"session"`
	Event        string       `json:"event"`
	ReportDigest string       `json:"report_digest"`
	Report       HealthReport `json:"report"`
}

// localHealth is deliberately a small, versioned set of local heuristics.
// No flag is a strength certificate or a breach/website-2FA status claim.
func localHealth(items []vault.Item, revisions map[string]string) (HealthReport, error) {
	report := HealthReport{Profile: "local-heuristics-v1", Scope: "active-logins", Findings: []HealthFinding{}}
	counts := map[string]int{}
	for _, it := range items {
		if it.Kind == "login" && it.State == "" && it.Password != "" {
			counts[it.Password]++
		}
	}
	for _, it := range items {
		if it.Kind != "login" || it.State != "" {
			report.Skipped++
			continue
		}
		if !idOK(it.ID) || !digestOK(revisions[it.ID]) {
			return HealthReport{}, invalid
		}
		report.Checked++
		flags := []string{}
		if it.Password == "" {
			flags = append(flags, "empty")
		} else {
			if utf8.RuneCountInString(it.Password) < 12 {
				flags = append(flags, "short")
			}
			distinct := map[rune]bool{}
			for _, r := range it.Password {
				distinct[r] = true
			}
			if len(distinct) < 4 {
				flags = append(flags, "low-variety")
			}
			switch strings.ToLower(it.Password) {
			case "password", "password123", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwerty123", "letmein", "welcome", "admin", "iloveyou":
				flags = append(flags, "common-example")
			}
			if counts[it.Password] > 1 {
				flags = append(flags, "reused")
			}
		}
		if it.OTP == "" {
			flags = append(flags, "totp-not-stored")
		}
		if len(flags) > 0 {
			report.Findings = append(report.Findings, HealthFinding{ID: it.ID, Revision: revisions[it.ID], Flags: flags})
		}
	}
	sort.Slice(report.Findings, func(i, j int) bool { return report.Findings[i].ID < report.Findings[j].ID })
	return report, nil
}

// Health releases only versioned item identifiers and fixed findings after
// the authenticated audit commits and the database closes successfully.
func Health(path, pw string, key []byte) (HealthReceipt, error) {
	r, err := command(path, pw, key, healthAction, vault.Item{}, nil)
	if err != nil {
		return HealthReceipt{}, err
	}
	return HealthReceipt{Status: "checked-local", Session: r.session, Event: r.intent, ReportDigest: r.reportDigest, Report: r.health}, nil
}
