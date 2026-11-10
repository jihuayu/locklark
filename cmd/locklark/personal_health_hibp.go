package main

// Explicit HIBP opt-in for `personal health`.
//
// The default `personal health --file PATH` path remains the exact offline
// `local-heuristics-v1` receipt produced by personal.Health. Only the literal
// option pair `--hibp true` reaches this file. Before any unlock or audit the
// user must see a fixed privacy warning and type the hidden NETWORK consent.
// A missing or wrong consent returns a fixed refusal, performs no vault
// transaction and creates no health network intent.
//
// The outbound transport is the existing production HIBPClient owned by the
// unlocked Session; tests use package-local fake or synthetic TLS transports,
// never a production endpoint hook.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/watchtower"
)

const (
	personalHIBPDeadline = 30 * time.Second
	personalHIBPIdle     = time.Minute
)

// errPersonalHIBPCancelled is the fixed refusal for a missing or wrong NETWORK
// consent. It never includes terminal input, a prefix or provider details.
var errPersonalHIBPCancelled = errors.New("HIBP network check cancelled")

// personalHIBPOutput is the CLI-only safe projection. The native Watchtower
// report also carries titles and origins, so it must never be JSON-encoded
// directly by the CLI.
type personalHIBPOutput struct {
	Status      string                `json:"status"`
	HIBPChecked bool                  `json:"hibp_checked"`
	HIBPError   string                `json:"hibp_error,omitempty"`
	Checked     int                   `json:"checked"`
	Skipped     int                   `json:"skipped"`
	Findings    []personalHIBPFinding `json:"findings"`
}

type personalHIBPFinding struct {
	ID          string   `json:"id"`
	Revision    string   `json:"revision"`
	Flags       []string `json:"flags"`
	BreachCount int      `json:"breach_count"`
}

// confirmPersonalHIBP prints the fixed pre-network warning and reads the hidden
// NETWORK consent. It runs before UnlockSession, so a refusal cannot create a
// desktop.unlock or vault.health.hibp audit event.
func confirmPersonalHIBP(ask func(string) ([]byte, error), out io.Writer) error {
	if ask == nil || out == nil {
		return errPersonalHIBPCancelled
	}
	if _, err := fmt.Fprint(out, "安全体检 — 显式启用 HIBP 泄露库查询\r\n  检查范围：仅当前活动登录（不含归档、回收站或导入来源旧值）\r\n  查询端点：https://api.pwnedpasswords.com/range/（请求头 Add-Padding: true，不携带 Cookie）\r\n  发送内容：仅每个非空密码 SHA-1 的前 5 个十六进制字符；不会发送明文密码、完整哈希或哈希后缀。\r\n  隐私提示：查询前缀与来源 IP 仍会暴露给 HIBP 并可能被关联；未发现问题不代表密码绝对安全，未保存 TOTP 也不代表网站未启用双因素。\r\n  取消保障：取消或未确认时不会联网，也不会写入联网意图审计。\r\n"); err != nil {
		return err
	}
	consent, err := ask("输入 NETWORK 确认联网查询泄露前缀")
	defer clear(consent)
	if err != nil {
		return err
	}
	if string(consent) != "NETWORK" {
		return errPersonalHIBPCancelled
	}
	return nil
}

// personalHealthHIBP performs the consented, authenticated opt-in check. The
// 30-second context bounds the whole multi-prefix lookup; the existing client
// keeps its 10-second per-request timeout. Credentials come from the normal
// master-password plus Secret Key prompts, never quick unlock or environment
// state.
func personalHealthHIBP(path, pw string, key []byte, ask func(string) ([]byte, error), out io.Writer) (any, error) {
	if path == "" || len(pw) == 0 || len(key) != 16 {
		return nil, errPersonalHIBPCancelled
	}
	if err := confirmPersonalHIBP(ask, out); err != nil {
		return nil, err
	}
	session, err := personal.UnlockSession(path, []byte(pw), key, personalHIBPIdle)
	if err != nil {
		return nil, err
	}
	defer session.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), personalHIBPDeadline)
	defer cancel()
	report, err := session.WatchtowerContext(ctx, "", true)
	if err != nil {
		return nil, err
	}
	return projectPersonalHIBP(report), nil
}

// projectPersonalHIBP keeps only the reviewed non-secret fields. Titles,
// origins, URLs, passwords, full hashes, prefixes, suffixes and raw provider
// errors are dropped. HIBPError is additionally whitelisted to its single
// fixed value.
func projectPersonalHIBP(report watchtower.Report) personalHIBPOutput {
	hibpError := report.HIBPError
	if hibpError != "" && hibpError != "unavailable" {
		hibpError = "unavailable"
	}
	status := "checked-hibp"
	if !report.HIBPChecked {
		status = "hibp-unavailable"
	}
	findings := make([]personalHIBPFinding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		findings = append(findings, personalHIBPFinding{
			ID:          finding.ID,
			Revision:    finding.Revision,
			Flags:       append([]string{}, finding.Flags...),
			BreachCount: finding.BreachCount,
		})
	}
	return personalHIBPOutput{
		Status:      status,
		HIBPChecked: report.HIBPChecked,
		HIBPError:   hibpError,
		Checked:     report.Checked,
		Skipped:     report.Skipped,
		Findings:    findings,
	}
}
