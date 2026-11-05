# 单字段 JSON 配置注入

基线 main `a078a75`（PR #15 本地体检），分支 `codex/personal-json-injection`。命令：`personal inject-json --file owner.ll --id ID --revision REV --field username|password --name PROPERTY --out NEW.json`。隐藏双因素、显示目标/修订/属性/文件路径并输入 WRITE 后，输出仅含该属性的 JSON 文件。原值按 JSON 转义，换行/引号/反斜线均保留；不执行模板、shell 或子进程，不宣称通用 op inject/run 兼容。OTP 种子不在此入口范围。

解锁并验证完整历史后，核对条目身份和精确修订，再拒绝回收站；明确指定的归档项与直接人工披露规则一致，仍可使用。`item.inject.username/password` 的 intent 与当前修订绑定，Link 使用本库密钥经独立用途 HKDF/HMAC 绑定 `json-single-field-v1`、绝对目标路径和属性名。审计不保存路径/属性明文或字段指纹。绑定是指定路径字符串，不是目标文件永久身份或内容证明；文件之后可能被修改。

只有审计提交和数据库成功关闭后才创建输出。临时文件与目标同目录，完整写入/fsync/关闭后不覆盖发布。已有文件或链接不会被覆盖，失败不返回成功回执，也不透传可能包含秘密的文件系统/自定义 writer 错误。回执只含固定状态、session、intent 和目的绑定；intent 不能证明文件被读取，失败/崩溃可能已留下输出或临时文件，清理不等于安全擦除。

Unix 临时文件从创建起为 0600。Windows 使用 CreateFile 的 SecurityAttributes，在创建时设置仅当前账户读取的 protected DACL，禁继承并在持有句柄期间不共享；不会先写出秘密再改 ACL。Windows 原生测试同时检查初始句柄和发布后文件的 DACL。调用者应使用自己控制的目录；文件权限不能隔离同账户进程或系统管理员，输出是需自行管理的明文。此入口不增加 MCP/Agent 原值工具。

失败先行日志 `/tmp/locklark-validation/injection-red.log`。定向测试覆盖 JSON 字节还原、目的/修订审计、错误因素、旧修订、回收站、事务回滚不触达 writer、不覆盖、临时文件正常清理和错误消息脱敏；Linux 真实 PTY 脚本 `scripts/injection_acceptance.py` 已通过。Windows 交叉编译不替代原生 DACL/ConPTY，最终运行与 Luna/max 独立复核以本批 PR 为准。
