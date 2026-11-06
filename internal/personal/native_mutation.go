package personal

import (
	"errors"
	"strings"

	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrMutationRefused = errors.New("native mutation refused")
var ErrMutationCancelled = errors.New("native mutation cancelled before persistence")
var ErrMutationUnknown = errors.New("native operation result unknown; inspect the vault before retrying")

type NativeLoginMetadata struct{ Title, URL string }
type NativeLoginView struct{ ID, Revision, Title, URL, State string }
type nativeMutationRequest struct{ gate *MutationGate }

func (s *Session) RegisterMutation(g *MutationGate) error {
	if e := s.RegisterBrowserSave(g); e != nil {
		return ErrMutationCancelled
	}
	return nil
}
func (s *Session) ReleaseMutation(g *MutationGate) { s.ReleaseBrowserSave(g) }
func (s *Session) registeredMutation(g *MutationGate) bool {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	return g != nil && s.saveGate == g && g.Pending() && !s.lockRequested.Load()
}
func (s *Session) nativeMutation(action string, add vault.Item, edit *Edit, option commandOption, g *MutationGate) (result, error) {
	return s.nativeMutationWith(action, add, edit, option, g, nil)
}
func (s *Session) nativeMutationWith(action string, add vault.Item, edit *Edit, option commandOption, g *MutationGate, run func(commandOption) (result, error)) (result, error) {
	return s.nativeMutationWithTouch(action, add, edit, option, g, run, true)
}
func (s *Session) nativeMutationWithTouch(action string, add vault.Item, edit *Edit, option commandOption, g *MutationGate, run func(commandOption) (result, error), touch bool) (result, error) {
	defer func() {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(touch) != nil {
		return result{}, ErrMutationCancelled
	}
	option.unlocked = s
	option.nativeMutation = &nativeMutationRequest{g}
	if run == nil {
		run = func(o commandOption) (result, error) { return command(s.path, "", nil, action, add, edit, o) }
	}
	r, e := run(option)
	if errors.Is(e, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if g.CommitWon() && (!active || e != nil && !errors.Is(e, ErrConflict) && !errors.Is(e, ErrNotFound) && !errors.Is(e, ErrTrashed) && !errors.Is(e, ErrMutationRefused) && !errors.Is(e, ErrOTPNotConfigured) && !errors.Is(e, ErrBrowserOTP)) {
		if r.otp != nil {
			r.otp.Clear()
		}
		return result{}, ErrMutationUnknown
	}
	if !active {
		if r.otp != nil {
			r.otp.Clear()
		}
		return result{}, ErrMutationCancelled
	}
	return r, e
}
func (s *Session) SaveNativeLogin(meta NativeLoginMetadata, user, value []byte, g *MutationGate) (GenerationReceipt, error) {
	defer clear(user)
	defer clear(value)
	r, e := s.nativeMutation("item.add", vault.Item{Kind: "login", Title: meta.Title, URL: meta.URL, Username: string(user), Password: string(value)}, nil, commandOption{}, g)
	if e != nil {
		return GenerationReceipt{}, e
	}
	return GenerationReceipt{r.id, r.revision, r.profile}, nil
}
func (s *Session) GenerateNativeLogin(meta NativeLoginMetadata, user []byte, length int, g *MutationGate) (GenerationReceipt, error) {
	defer clear(user)
	option := commandOption{generation: &generationRequest{policy: password.Policy{Length: length, Alphabet: password.DefaultAlphabet}, generate: password.Generate}}
	r, e := s.nativeMutation("item.generate", vault.Item{Kind: "login", Title: meta.Title, URL: meta.URL, Username: string(user)}, nil, option, g)
	if e != nil {
		return GenerationReceipt{}, e
	}
	return GenerationReceipt{r.id, r.revision, r.profile}, nil
}
func (s *Session) RegenerateNativePassword(id, revision string, length int, g *MutationGate) (GenerationReceipt, error) {
	if !ValidEditTarget(id, revision, "password") {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return GenerationReceipt{}, ErrMutationRefused
	}
	option := commandOption{generation: &generationRequest{policy: password.Policy{Length: length, Alphabet: password.DefaultAlphabet}, generate: password.Generate}}
	r, e := s.nativeMutation("item.regenerate.password", vault.Item{}, &Edit{ID: id, Revision: revision, Field: "password"}, option, g)
	if e != nil {
		return GenerationReceipt{}, e
	}
	return GenerationReceipt{r.id, r.revision, r.profile}, nil
}
func (s *Session) ReviewNativeLogin(id, revision string) (NativeLoginView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidEditTarget(id, revision, "password") {
		return NativeLoginView{}, ErrMutationRefused
	}
	if e := s.active(true); e != nil {
		return NativeLoginView{}, e
	}
	var view NativeLoginView
	e := s.readNativeTarget(id, revision, func(item vault.Item) error {
		state := item.State
		if state == "" {
			state = "active"
		}
		view = NativeLoginView{item.ID, revision, item.Title, item.URL, state}
		return nil
	})
	if e == nil {
		e = s.active(false)
	}
	if e != nil {
		return NativeLoginView{}, e
	}
	return view, nil
}
func validNativeNew(add vault.Item) bool {
	return strings.TrimSpace(add.Title) != "" && len(add.Title) <= 1024 && validBrowserText([]byte(add.Title)) && validBrowserText([]byte(add.Username)) && validateEditValue(Edit{Field: "url", Value: add.URL}) == nil
}
