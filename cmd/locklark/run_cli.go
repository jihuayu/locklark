package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/jihuayu/locklark/internal/personal"
)

type childExitStatus struct{ code int }

var errRunCLIConsole = errors.New("personal run-cli requires an interactive terminal with a controlling console for hidden input and prompts")

func (*childExitStatus) Error() string { return "local child exited unsuccessfully" }

func confirmRunCLI(c *console, target personal.RevealTarget, r personal.RunCLIRequest) error {
	if _, e := fmt.Fprintf(c.output(), "可信命令凭据披露确认（personal run-cli）\r\n  目标条目：%s @ %s（字段 password -> 环境变量 %s）\r\n  执行程序：%s\r\n  工作目录：%s\r\n  Profile ：%s\r\n  超时上限：%d 秒\r\n安全提示：\r\n  - 这不是沙箱，也无法收回已披露的值：子进程及后代可读取、打印、联网或保存 token。\r\n  - 直连当前终端标准输入/输出/错误；Locklark 不捕获或记录子进程输出正文。\r\n  - 净化环境：不继承代理、调试、其他 token 或动态加载器变量；HOME/GH/XDG/临时目录仅供本次运行使用，gh profile 拒绝 auth login 与 setup-git。\r\n  - 超时仅尝试终止直接子进程，后代可能继续运行；中断或清理失败时结果可能未知。\r\n辅助 PATH：\r\n", target.ID, target.Revision, r.Name, strconv.QuoteToASCII(r.Program), strconv.QuoteToASCII(r.Directory), r.Profile, r.TimeoutSeconds); e != nil {
		return e
	}
	if len(r.HelperPath) == 0 {
		if _, e := fmt.Fprint(c.output(), "  （无）\r\n"); e != nil {
			return e
		}
	}
	for _, path := range r.HelperPath {
		if _, e := fmt.Fprintf(c.output(), "  %s\r\n", strconv.QuoteToASCII(path)); e != nil {
			return e
		}
	}
	if _, e := fmt.Fprint(c.output(), "命令参数（会显示在终端与系统进程列表中，请勿在参数内写入秘密）：\r\n"); e != nil {
		return e
	}
	if len(r.Args) == 0 {
		if _, e := fmt.Fprint(c.output(), "  （无）\r\n"); e != nil {
			return e
		}
	}
	for i, arg := range r.Args {
		if _, e := fmt.Fprintf(c.output(), "  [%d] %s\r\n", i, strconv.QuoteToASCII(arg)); e != nil {
			return e
		}
	}
	consent, e := c.field("输入 RUN 确认本次可信命令披露")
	defer clear(consent)
	if e != nil {
		return e
	}
	if string(consent) != "RUN" {
		return errors.New("local process cancelled")
	}
	return nil
}
