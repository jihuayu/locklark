//go:build (!linux && !windows && !darwin) || (darwin && !cgo)

package osunlock

type unavailable struct{}

func New() Store    { return unavailable{} }
func Label() string { return "系统解锁不可用" }
func Biometry() string {
	return "不可用"
}
func Description() string {
	return "此构建未提供系统密钥适配器，请使用完整解锁。"
}
func Requirement() string {
	return "此构建或平台没有可用的系统密钥适配器。"
}
func (unavailable) Store(string, []byte) error  { return ErrUnavailable }
func (unavailable) Load(string) ([]byte, error) { return nil, ErrUnavailable }
func (unavailable) Delete(string) error         { return ErrUnavailable }
