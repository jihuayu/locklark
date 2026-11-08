package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestImportCommandRequiresPlanDigestAndTerminal(t *testing.T) {
	for _, args := range [][]string{
		{"import-1pux", "--file", "vault", "--source", "source"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", "bad"},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--digest", strings.Repeat("0", 64)},
	} {
		if err := runPersonal(args, &bytes.Buffer{}); err != personalUsage {
			t.Fatal("invalid import shape", err)
		}
	}
	for _, args := range [][]string{
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", strings.Repeat("0", 64)},
		{"plan-import-1pux", "--file", "vault", "--source", "source"},
	} {
		err := runPersonal(args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
			t.Fatal("missing terminal boundary", err)
		}
	}
}

func TestImportModelFlagShape(t *testing.T) {
	digest := strings.Repeat("0", 64)
	for _, args := range [][]string{
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model", "v3"},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model", "basic"},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model", "1pux-full-v2"},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model"},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model", ""},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model", "v2", "--digest", digest},
		{"plan-import-1pux", "--file", "vault", "--source", "", "--model", "v2"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", digest, "--model", "v3"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", digest, "--model", "basic"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", "bad", "--model", "v2"},
		{"import-1pux", "--file", "vault", "--source", "source", "--model", "v2"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", digest, "--model", "v2", "--backend", "recorded-response/v1"},
	} {
		if err := runPersonal(args, &bytes.Buffer{}); err != personalUsage {
			t.Fatalf("invalid model shape accepted: %q: %v", args, err)
		}
	}
}

func TestImportModelFlagKeepsTerminalBoundary(t *testing.T) {
	digest := strings.Repeat("0", 64)
	for _, args := range [][]string{
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--model", "v2"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", digest, "--model", "v2"},
	} {
		out := &bytes.Buffer{}
		err := runPersonal(args, out)
		if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
			t.Fatalf("v2 shape did not reach the terminal boundary: %q: %v", args, err)
		}
		if out.Len() != 0 {
			t.Fatal("wrote JSON before the terminal boundary")
		}
	}
	for _, args := range [][]string{
		{"plan-import-1pux", "--file", "vault", "--source", "source"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", digest},
	} {
		err := runPersonal(args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
			t.Fatalf("legacy shape changed: %q: %v", args, err)
		}
	}
}

func TestImportNoticeMatchesProfile(t *testing.T) {
	if legacy := personalImportNotice(false); legacy != "仅支持单账户、单库的基本登录；未支持的类别、字段、历史和附件会整批拒绝。\r\n来源记录会加密保留，可能保留以后修改前的旧值；不会覆盖已有条目。\r\n" {
		t.Fatal("legacy import notice changed")
	}
	v2 := personalImportNotice(true)
	for _, want := range []string{"类别", "分节", "标签", "收藏", "附件", "原子拒绝", "不会覆盖", "加密保留"} {
		if !strings.Contains(v2, want) {
			t.Fatalf("v2 notice missing %q", want)
		}
	}
	if strings.Contains(v2, "仅支持单账户、单库的基本登录") {
		t.Fatal("v2 notice describes the narrow login profile")
	}
}

func TestImportConsentMatchesAction(t *testing.T) {
	if prompt, answer := personalImportConsent("plan-import-1pux"); prompt != "输入 PLAN 确认生成导入计划" || answer != "PLAN" {
		t.Fatalf("plan consent changed: %q %q", prompt, answer)
	}
	if prompt, answer := personalImportConsent("import-1pux"); prompt != "输入 SAVE 确认整批导入" || answer != "SAVE" {
		t.Fatalf("import consent changed: %q %q", prompt, answer)
	}
}
