package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// This fixture helper uses the ordinary authenticated edit API. It does not
// affect approval or add a product-only acceptance path.
func setOTP(f fixture, digits int) error {
	if digits != 0 && digits != 6 && digits != 8 {
		return errors.New("invalid synthetic digits")
	}
	key, err := personal.ParseSecret(f.Secret)
	if err != nil {
		return err
	}
	defer clear(key)
	session, err := personal.UnlockSession(f.Path, []byte(f.Password), key, time.Minute)
	if err != nil {
		return err
	}
	defer session.Lock()
	rows, err := session.List("active")
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID != f.SeedID {
			continue
		}
		value := ""
		if digits != 0 {
			value = fmt.Sprintf("otpauth://totp/browser-synthetic?secret=%s&digits=%d", f.OTPSeed, digits)
		}
		_, err = session.Edit(personal.Edit{ID: row.ID, Revision: row.Revision, Field: "otp", Value: value})
		return err
	}
	return errors.New("synthetic seed absent")
}
func configureOTP(input string, digits int) error {
	raw, err := os.ReadFile(input)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("invalid synthetic fixture")
	}
	defer clear(raw)
	var f fixture
	if json.Unmarshal(raw, &f) != nil || f.Path != filepath.Join(filepath.Dir(input), "synthetic.ll") {
		return errors.New("invalid synthetic fixture path")
	}
	return setOTP(f, digits)
}
