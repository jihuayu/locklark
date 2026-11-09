package osunlock

import "github.com/egoist/mygo"

type keyring struct{}

func New() Store    { return keyring{} }
func Label() string { return "系统钥匙串" }
func Description() string {
	return "由 Secret Service 保护；已解锁的系统钥匙串可能不再次提示，同一系统用户的其他程序可能有权读取。24 小时后需完整解锁。"
}
func Requirement() string {
	return "需要当前桌面会话提供 Secret Service；已解锁的钥匙串可能不会逐次要求用户验证。"
}
func (keyring) Store(id string, b []byte) error {
	if !validID(id) || len(b) > mygo.MaxSecretSize {
		return ErrUnavailable
	}
	if mygo.Secrets.Service("app.locklark.unlock.v1").Set(id, b) != nil {
		return ErrUnavailable
	}
	return nil
}
func (keyring) Load(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	b, e := mygo.Secrets.Service("app.locklark.unlock.v1").Get(id)
	if e != nil {
		clear(b)
		return nil, ErrUnavailable
	}
	return b, nil
}
func (keyring) Delete(id string) error {
	if !validID(id) {
		return ErrUnavailable
	}
	if mygo.Secrets.Service("app.locklark.unlock.v1").Delete(id) != nil {
		return ErrUnavailable
	}
	return nil
}
