package preview

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/gateway"
	"io"
	"time"
)

func safeRepo(r gateway.Repository) bool { return !looksSensitive(r.Owner) && !looksSensitive(r.Name) }
func validPullInput(session, reason, ref string, p *gateway.PullIntent) bool {
	return p != nil && p.Valid() && ref == p.Slot && safeRepo(p.Repo) && validReason(reason) && validSession(session) && session != systemSession
}
func supportedAction(q Request) bool {
	return q.Epoch == 3 && (q.Action == FixtureAction && q.Ref == FixtureRef && q.Pull == nil || q.Action == gateway.PullAction && validPullInput(q.Session, q.Reason, q.Ref, q.Pull))
}
func EnrollPullSession(device, session, public, reason string, repo gateway.Repository) (SessionChange, error) {
	scope, err := gateway.RecordedScope(repo)
	if err != nil || !safeRepo(repo) {
		return SessionChange{}, errSession
	}
	return changeScopedSession(device, session, public, reason, false, time.Now, &scope)
}
func SubmitPullReceipt(inbox, recipient, session, reason, key string, repo gateway.Repository, n int, proposal []byte) (Submitted, error) {
	var receipt Submitted
	p, err := gateway.RecordedIntent(repo, n, proposal)
	if err != nil {
		return receipt, err
	}
	_, err = submit(inbox, recipient, session, reason, gateway.PullSlot, key, &receipt, &p)
	return receipt, err
}
func SubmitPullFile(inbox, recipient, session, reason, key string, repo gateway.Repository, n int, path string) (Submitted, error) {
	plan, err := readPath(path, 4096)
	if err != nil {
		return Submitted{}, err
	}
	return SubmitPullReceipt(inbox, recipient, session, reason, key, repo, n, plan)
}
func InvokeRecordedPull(device, bundle, ticket, responseFile string) ([]byte, error) {
	if responseFile == "" {
		return nil, errInput
	}
	response, err := readPath(responseFile, 1<<20)
	if err != nil {
		return nil, errInvoke
	}
	defer clear(response)
	return runBoundAction(device, bundle, ticket, gateway.PullAction, func(q Request, archive []byte) (signedReply, error) {
		result, err := q.Pull.ReadRecording(context.Background(), response, func() ([]byte, error) { return fixturePasswordField(archive) })
		return signedReply{Pull: &RecordedResult{Source: q.Pull.Backend, Pull: result}}, err
	}, time.Now)
}
func fixturePasswordField(raw []byte) ([]byte, error) {
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, errInvoke
	}
	f, err := z.Open("export.data")
	if err != nil {
		return nil, errInvoke
	}
	defer f.Close()
	var v struct {
		Accounts []struct {
			Attrs  struct{ UUID string }
			Vaults []struct {
				Attrs struct{ UUID string }
				Items []struct {
					UUID    string
					Details struct {
						LoginFields []struct{ Name, Designation, Value string }
					}
				}
			}
		}
	}
	if json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&v) != nil {
		return nil, errInvoke
	}
	for _, a := range v.Accounts {
		if a.Attrs.UUID != "synthetic-account" {
			continue
		}
		for _, vault := range a.Vaults {
			if vault.Attrs.UUID != "synthetic-vault" {
				continue
			}
			for _, it := range vault.Items {
				if it.UUID != "login-sample" {
					continue
				}
				for _, field := range it.Details.LoginFields {
					if field.Name == "password" && field.Designation == "password" && field.Value != "" {
						return []byte(field.Value), nil
					}
				}
			}
		}
	}
	return nil, errInvoke
}
