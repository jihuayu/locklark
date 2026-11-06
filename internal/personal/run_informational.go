package personal

import (
	"context"
	"os"
	"strings"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

// RunCLIInformational runs a pinned tool without opening the vault or rendering
// any credential slots. It uses the same private home/config/temp directories
// and explicit helper PATH as an authenticated run. Targets are metadata only.
func RunCLIInformational(ctx context.Context, request RunBundleRequest, targets []BundleTarget, tool string) (int, error) {
	return runCLIInformational(ctx, request, targets, tool, runCLIStreams{os.Stdin, os.Stdout, os.Stderr})
}

func runCLIInformational(ctx context.Context, request RunBundleRequest, targets []BundleTarget, tool string, streams runCLIStreams) (code int, retErr error) {
	if ctx == nil || request.Validate(targets) != nil || cliprofile.DefaultNeedsAuth(request.Args) || len(tool) == 0 || len(tool) > 64 {
		return 0, ErrRunTarget
	}
	for _, c := range tool {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return 0, ErrRunTarget
		}
	}
	if ctx.Err() != nil {
		return 0, ErrRunCancelled
	}
	request.Args = append([]string(nil), request.Args...)
	request.HelperPath = append([]string(nil), request.HelperPath...)
	request.Passthrough = cloneStringMap(request.Passthrough)
	root, err := createRunCLITemp()
	if err != nil {
		return 0, ErrRunTemporary
	}
	defer func() {
		if os.RemoveAll(root) != nil {
			code, retErr = 0, ErrRunCleanup
		}
	}()
	if err = makeBundleDirs(root, nil); err != nil {
		return 0, err
	}
	// Only explicitly selected non-secret passthrough values are inherited.
	// In particular, no profile slot, generated credential file, ambient token,
	// loader setting, or parent HOME/config path is available to this child.
	env := []string{"LOCKLARK_CLI_ACTIVE=" + tool}
	for name, value := range request.Passthrough {
		if strings.ContainsRune(value, 0) {
			return 0, ErrRunTarget
		}
		env = append(env, name+"="+value)
	}
	return executeRunBundle(ctx, request, root, cliprofile.RenderedBundle{Env: env}, streams)
}
