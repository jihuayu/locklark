package personal

import (
	"errors"

	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
)

type GenerationReceipt struct {
	ID       string           `json:"id"`
	Revision string           `json:"revision"`
	Profile  password.Profile `json:"profile"`
}

type generationRequest struct {
	policy   password.Policy
	generate func(password.Policy) (password.Secret, error)
}

func generatedAction(action string) bool {
	return action == "item.generate" || action == "item.regenerate.password"
}

func validGenerationProfile(profile password.Profile) bool {
	expected, err := password.Validate(password.Policy{Length: profile.Length, Alphabet: password.DefaultAlphabet})
	return err == nil && profile == expected
}

func generationOption(length int) (commandOption, error) {
	policy := password.Policy{Length: length, Alphabet: password.DefaultAlphabet}
	if _, err := password.Validate(policy); err != nil {
		return commandOption{}, err
	}
	return commandOption{generation: &generationRequest{policy: policy, generate: password.Generate}}, nil
}

func (request *generationRequest) value() (password.Secret, error) {
	if request == nil || request.generate == nil {
		return password.Secret{}, password.ErrRandom
	}
	secret, err := request.generate(request.policy)
	if err != nil {
		return password.Secret{}, password.ErrRandom
	}
	return secret, nil
}

// GenerateLogin generates only after authentication inside the write transaction.
// The generated value is never returned; explicit disclosure is a separate action.
func GenerateLogin(path, pw string, key []byte, title, username string, length int) (GenerationReceipt, error) {
	option, err := generationOption(length)
	if err != nil {
		return GenerationReceipt{}, err
	}
	r, err := command(path, pw, key, "item.generate", vault.Item{Kind: "login", Title: title, Username: username}, nil, option)
	if err != nil {
		return GenerationReceipt{}, err
	}
	return GenerationReceipt{r.id, r.revision, r.profile}, nil
}

// RegeneratePassword replaces only a local value. It does not change the
// password at any upstream service and refuses a stale observed revision.
func RegeneratePassword(path, pw string, key []byte, id, revision string, length int) (GenerationReceipt, error) {
	if !ValidEditTarget(id, revision, "password") {
		return GenerationReceipt{}, errors.New("invalid login ID or revision")
	}
	option, err := generationOption(length)
	if err != nil {
		return GenerationReceipt{}, err
	}
	r, err := command(path, pw, key, "item.regenerate.password", vault.Item{}, &Edit{ID: id, Revision: revision, Field: "password"}, option)
	if err != nil {
		return GenerationReceipt{}, err
	}
	return GenerationReceipt{r.id, r.revision, r.profile}, nil
}
