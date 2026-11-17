//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	nativeFenceChildCaseEnv        = "LOCKLARK_NATIVE_LIFECYCLE_CHILD_CASE"
	nativeFenceChildArtifactDirEnv = "LOCKLARK_NATIVE_LIFECYCLE_ARTIFACT_DIR"

	nativeFenceChildCommandTimeout = 35 * time.Second
	nativeFenceChildTestTimeout    = "30s"
)

// nativeFenceRunIsolatedChild executes the frozen test binary again with the
// exact child case. The child has its own process-local factory/singletons and
// creates its own pipes/fixtures. Only test-only finite case names and private
// artifact paths cross the exec boundary.
func nativeFenceRunIsolatedChild(t *testing.T, caseName, childTest string) {
	t.Helper()
	if os.Getenv(nativeFenceChildCaseEnv) != "" {
		t.Skip("native fence isolation child execution")
	}
	parentDir := os.Getenv(nativeFenceChildArtifactDirEnv)
	if parentDir == "" {
		parentDir = os.TempDir()
	}
	dir, err := os.MkdirTemp(parentDir, "locklark-native-fence-child-")
	if err != nil {
		t.Fatal("NATIVE_FENCE_CHILD_ARTIFACT_SUBDIR_FAILED")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		_ = os.Remove(dir)
		t.Fatal("NATIVE_FENCE_CHILD_ARTIFACT_SUBDIR_MODE_FAILED")
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	stdout, ok := nativeFenceChildCaptureFile(stdoutPath)
	if !ok {
		t.Fatal("NATIVE_FENCE_CHILD_STDOUT_CREATE_FAILED")
	}
	stderr, ok := nativeFenceChildCaptureFile(stderrPath)
	if !ok {
		_ = stdout.Close()
		t.Fatal("NATIVE_FENCE_CHILD_STDERR_CREATE_FAILED")
	}
	executable, err := os.Executable()
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		t.Fatal("NATIVE_FENCE_CHILD_EXECUTABLE_FAILED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeFenceChildCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable,
		"-test.run", "^"+childTest+"$",
		"-test.count=1",
		"-test.timeout="+nativeFenceChildTestTimeout,
		"-test.v")
	command.Env = nativeFenceChildEnvironment(os.Environ(), caseName, dir)
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	_ = stdout.Close()
	_ = stderr.Close()
	if runErr != nil {
		stdoutBytes, stdoutHash := nativeFenceChildFileInfo(stdoutPath)
		stderrBytes, stderrHash := nativeFenceChildFileInfo(stderrPath)
		t.Fatalf("NATIVE_FENCE_CHILD_FAILED case=%s stdout=%s bytes=%d sha256=%s stderr=%s bytes=%d sha256=%s",
			caseName, stdoutPath, stdoutBytes, stdoutHash, stderrPath, stderrBytes, stderrHash)
	}
	t.Logf("NATIVE_FENCE_CHILD_PASS case=%s stdout=%s stderr=%s", caseName, stdoutPath, stderrPath)
}

func nativeFenceChildCaptureFile(path string) (*os.File, bool) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, false
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, false
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		_ = file.Close()
		return nil, false
	}
	return file, true
}

func nativeFenceChildEnvironment(base []string, caseName, dir string) []string {
	env := make([]string, 0, len(base)+2)
	for _, entry := range base {
		switch {
		case strings.HasPrefix(entry, nativeFenceChildCaseEnv+"="):
			continue
		case strings.HasPrefix(entry, nativeFenceChildArtifactDirEnv+"="):
			continue
		case strings.HasPrefix(entry, nativeFenceFactoryControlEnv+"="):
			continue
		case strings.HasPrefix(entry, nativeFenceFactoryEventEnv+"="):
			continue
		default:
			env = append(env, entry)
		}
	}
	env = append(env,
		nativeFenceChildCaseEnv+"="+caseName,
		nativeFenceChildArtifactDirEnv+"="+dir)
	return env
}

func nativeFenceChildFileInfo(path string) (int64, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1, "unavailable"
	}
	return int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
}
