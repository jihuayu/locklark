package personal

import (
	"errors"
	"io"
	"io/fs"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/vault"
)

const inspectionAction = "migration.inspect.1pux"

var ErrInspectionSource = errors.New("cannot read 1PUX source as a bounded regular file")

type InspectionReceipt struct {
	Status       string        `json:"status"`
	Session      string        `json:"session"`
	Event        string        `json:"event"`
	ReportDigest string        `json:"report_digest"`
	Report       onepux.Report `json:"report"`
}

type inspectionRequest struct{ read func() ([]byte, error) }
type inspectionFile interface {
	io.Reader
	Stat() (fs.FileInfo, error)
	Close() error
}

func readInspectionFile(f inspectionFile) (data []byte, err error) {
	defer func() {
		if e := f.Close(); e != nil && err == nil {
			err = ErrInspectionSource
		}
		if err != nil {
			clear(data)
			data = nil
		}
	}()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 0 {
		return nil, ErrInspectionSource
	}
	if st.Size() > onepux.MaxArchive {
		return nil, onepux.ErrLimit
	}
	data, e = io.ReadAll(io.LimitReader(f, onepux.MaxArchive+1))
	if e != nil {
		return data, ErrInspectionSource
	}
	if len(data) > onepux.MaxArchive {
		return data, onepux.ErrLimit
	}
	return data, nil
}

func readInspectionSource(path string) ([]byte, error) {
	f, err := openArchive(path)
	if err != nil {
		return nil, ErrInspectionSource
	}
	return readInspectionFile(f)
}

func inspectionFailure(err error) (string, error) {
	switch {
	case errors.Is(err, onepux.ErrInvalid):
		return "invalid", onepux.ErrInvalid
	case errors.Is(err, onepux.ErrUnsupported):
		return "unsupported", onepux.ErrUnsupported
	case errors.Is(err, onepux.ErrLimit):
		return "limit", onepux.ErrLimit
	default:
		return "source-error", ErrInspectionSource
	}
}

func (request *inspectionRequest) inspect() (onepux.Report, error) {
	data, err := request.read()
	defer clear(data)
	if err != nil {
		return onepux.Report{}, err
	}
	return onepux.Inspect(data)
}

// InspectOnepux only inventories a bounded plaintext source. Authentication and
// inspection/audit share the transaction; commit and DB close precede release.
// The digest binds the report bytes, not a source identity or import approval.
func InspectOnepux(path, pw string, key []byte, source string) (InspectionReceipt, error) {
	if source == "" {
		return InspectionReceipt{}, ErrInspectionSource
	}
	r, err := command(path, pw, key, inspectionAction, vault.Item{}, nil, commandOption{inspection: &inspectionRequest{read: func() ([]byte, error) { return readInspectionSource(source) }}})
	if err != nil {
		return InspectionReceipt{}, err
	}
	return InspectionReceipt{Status: "inspected-unmapped", Session: r.session, Event: r.intent, ReportDigest: r.reportDigest, Report: r.inspection}, nil
}
