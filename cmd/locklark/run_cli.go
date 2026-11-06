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
	if _, e := fmt.Fprintf(c.output(), "将条目 %s（修订 %s）的 password 交给本次可信本地程序的环境变量 %s。\r\n这不是沙箱，也不能收回已披露的值：程序及后代可读取、打印、联网或保存 token。\r\n使用真实标准输入/输出/错误；Locklark 不捕获或记录子进程正文。\r\n不继承代理、debug、其他 token 或加载器环境；HOME/GH/XDG/临时目录仅供本次使用。辅助 PATH 仅使用下列显式目录。\r\nLocklark 不运行额外的 auth login 或写用户全局配置；gh profile 拒绝直接 auth login/setup-git。\r\n超时只尝试终止直接子进程，后代可能继续运行；中断或清理失败结果可能未知。\r\n程序：%s\r\n目录：%s\r\nprofile：%s\r\n超时：%d 秒\r\n辅助 PATH：\r\n", target.ID, target.Revision, r.Name, strconv.QuoteToASCII(r.Program), strconv.QuoteToASCII(r.Directory), r.Profile, r.TimeoutSeconds); e != nil {
		return e
	}
	for _, path := range r.HelperPath {
		if _, e := fmt.Fprintf(c.output(), "  %s\r\n", strconv.QuoteToASCII(path)); e != nil {
			return e
		}
	}
	if _, e := fmt.Fprint(c.output(), "参数会显示并出现在进程列表中，不要把秘密写入参数。\r\n参数：\r\n"); e != nil {
		return e
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
