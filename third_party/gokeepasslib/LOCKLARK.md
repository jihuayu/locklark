# KDBX 适配来源

本目录是 [gokeepasslib](https://github.com/tobischo/gokeepasslib) v3.7.1 的运行时 Go 文件、go.mod、go.sum 与原始 MIT 许可证。上游模块校验和：`h1:1zGDG4UaL/GMLNmFL2u+NxHnSUWyoUiLrK5R+NgcB9o=`。提交 `2e5d240` 单独保留未修改文件，未复制示例或上游测试。根 go.mod 指向本目录；`go mod verify` 不验证本地替换，所以升级时必须从新版本校验和重新对照，并重跑独立互操作测试。

本地改动集中在 header.go 的标准 Argon2id UUID 和 credentials.go 的 KDBX 4 分派。Argon2id 使用 Go 的 [x/crypto/argon2.IDKey](https://pkg.go.dev/golang.org/x/crypto/argon2#IDKey)，旧 Argon2d 使用原上游实现。这里是 Locklark 签名快照的专用依赖，只允许这两种 KDBX 4 KDF，参数先校验再转换；不是通用 KeePass 导入器。

复跑 `TestKDBXIndependentPeer` 的步骤见根 README。这个测试通过标准输入传递一次性合成文件钥，不向产品新增钥匙导出能力。
