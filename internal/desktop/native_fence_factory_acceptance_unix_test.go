//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type nativeFenceFactoryTestPipes struct {
	controlIn     int
	controlOut    int
	eventIn       int
	eventOut      int
	ownsControlIn bool
	ownsEventOut  bool
}

func nativeFenceFactoryNewPipes(t *testing.T) *nativeFenceFactoryTestPipes {
	t.Helper()
	controlIn, controlOut := nativeFenceFactoryTestPipe(t)
	eventIn, eventOut := nativeFenceFactoryTestPipe(t)
	pipes := &nativeFenceFactoryTestPipes{
		controlIn:     controlIn,
		controlOut:    controlOut,
		eventIn:       eventIn,
		eventOut:      eventOut,
		ownsControlIn: true,
		ownsEventOut:  true,
	}
	t.Cleanup(func() {
		if pipes.ownsControlIn {
			nativeFenceFactoryTestClose(controlIn)
		}
		if pipes.ownsEventOut {
			nativeFenceFactoryTestClose(eventOut)
		}
		nativeFenceFactoryTestClose(controlOut)
		nativeFenceFactoryTestClose(eventIn)
	})
	return pipes
}

func (p *nativeFenceFactoryTestPipes) transfer() {
	p.ownsControlIn = false
	p.ownsEventOut = false
}

func nativeFenceFactoryTestPipe(t *testing.T) (int, int) {
	t.Helper()
	fds := []int{-1, -1}
	if err := syscall.Pipe(fds); err != nil {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_PIPE_CREATE_FAILED")
	}
	return fds[0], fds[1]
}

func nativeFenceFactoryTestClose(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

func nativeFenceFactoryTestFDOpen(fd int) bool {
	var stat syscall.Stat_t
	return syscall.Fstat(fd, &stat) == nil
}

func nativeFenceFactoryTestRequireInvalid(t *testing.T, transport *nativeFenceTransport) {
	t.Helper()
	if transport == nil {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_INVALID_RESULT_NIL")
	}
	if transport.config != nativeFenceConfigInvalid {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_INVALID_CONFIG_NOT_REPORTED")
	}
	if transport.controlInFD != -1 || transport.eventOutFD != -1 {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_INVALID_OWNS_DESCRIPTOR")
	}
}

func nativeFenceFactoryEnvScope(t *testing.T) func(string, bool, string, bool) {
	t.Helper()
	controlBefore, controlPresent := os.LookupEnv(nativeFenceFactoryControlEnv)
	eventBefore, eventPresent := os.LookupEnv(nativeFenceFactoryEventEnv)
	t.Cleanup(func() {
		nativeFenceFactoryRestoreEnv(nativeFenceFactoryControlEnv, controlBefore, controlPresent)
		nativeFenceFactoryRestoreEnv(nativeFenceFactoryEventEnv, eventBefore, eventPresent)
	})
	return func(controlValue string, controlSet bool, eventValue string, eventSet bool) {
		if controlSet {
			t.Setenv(nativeFenceFactoryControlEnv, controlValue)
		} else {
			_ = os.Unsetenv(nativeFenceFactoryControlEnv)
		}
		if eventSet {
			t.Setenv(nativeFenceFactoryEventEnv, eventValue)
		} else {
			_ = os.Unsetenv(nativeFenceFactoryEventEnv)
		}
	}
}

func nativeFenceFactoryRestoreEnv(name, value string, present bool) {
	if present {
		_ = os.Setenv(name, value)
		return
	}
	_ = os.Unsetenv(name)
}

func TestNativeFenceFactoryConfigSelection(t *testing.T) {
	t.Run("missing-both-disabled", func(t *testing.T) {
		transport := nativeFenceFactoryFromValues("", false, "", false)
		if transport != nil {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_MISSING_BOTH_NOT_DISABLED")
		}
	})

	cases := []struct {
		name           string
		controlValue   string
		controlPresent bool
		eventValue     string
		eventPresent   bool
	}{
		{name: "empty-control", controlValue: "", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "empty-event", controlValue: "7", controlPresent: true, eventValue: "", eventPresent: true},
		{name: "partial-control", controlValue: "7", controlPresent: true},
		{name: "partial-event", eventValue: "7", eventPresent: true},
		{name: "negative", controlValue: "-1", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "plus", controlValue: "+7", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "leading-space", controlValue: " 7", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "trailing-space", controlValue: "7 ", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "trailing-newline", controlValue: "7\n", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "leading-zero", controlValue: "07", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "overlong", controlValue: strings.Repeat("1", nativeFenceFactoryFDInputLimit+1), controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "overflow", controlValue: "4294967296", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "stdio-zero", controlValue: "0", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "stdio-one", controlValue: "1", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "stdio-two", controlValue: "2", controlPresent: true, eventValue: "7", eventPresent: true},
		{name: "same", controlValue: "7", controlPresent: true, eventValue: "7", eventPresent: true},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			transport := nativeFenceFactoryFromValues(
				testCase.controlValue, testCase.controlPresent,
				testCase.eventValue, testCase.eventPresent)
			nativeFenceFactoryTestRequireInvalid(t, transport)
		})
	}
}

func TestNativeFenceFactoryParserErrorPreservesCallerDescriptors(t *testing.T) {
	t.Run("malformed-control", func(t *testing.T) {
		pipes := nativeFenceFactoryNewPipes(t)
		transport := nativeFenceFactoryFromValues(
			"not-a-descriptor", true, strconv.Itoa(pipes.eventOut), true)
		nativeFenceFactoryTestRequireInvalid(t, transport)
		if !nativeFenceFactoryTestFDOpen(pipes.controlIn) || !nativeFenceFactoryTestFDOpen(pipes.eventOut) {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_PARSE_ERROR_CLOSED_CALLER_FD")
		}
	})

	t.Run("partial-control", func(t *testing.T) {
		pipes := nativeFenceFactoryNewPipes(t)
		transport := nativeFenceFactoryFromValues(
			strconv.Itoa(pipes.controlIn), true, "", false)
		nativeFenceFactoryTestRequireInvalid(t, transport)
		if !nativeFenceFactoryTestFDOpen(pipes.controlIn) {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_PARTIAL_CLOSED_CALLER_FD")
		}
	})

	t.Run("stdio-control", func(t *testing.T) {
		pipes := nativeFenceFactoryNewPipes(t)
		transport := nativeFenceFactoryFromValues(
			"0", true, strconv.Itoa(pipes.eventOut), true)
		nativeFenceFactoryTestRequireInvalid(t, transport)
		if !nativeFenceFactoryTestFDOpen(pipes.eventOut) {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_STDIO_CLOSED_CALLER_FD")
		}
	})

	t.Run("same-descriptor", func(t *testing.T) {
		pipes := nativeFenceFactoryNewPipes(t)
		same := strconv.Itoa(pipes.controlIn)
		transport := nativeFenceFactoryFromValues(same, true, same, true)
		nativeFenceFactoryTestRequireInvalid(t, transport)
		if !nativeFenceFactoryTestFDOpen(pipes.controlIn) {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_SAME_CLOSED_CALLER_FD")
		}
	})
}

func TestNativeFenceFactoryAcceptsDedicatedPipePair(t *testing.T) {
	pipes := nativeFenceFactoryNewPipes(t)
	transport := nativeFenceFactoryFromValues(
		strconv.Itoa(pipes.controlIn), true, strconv.Itoa(pipes.eventOut), true)
	if transport == nil {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_ACCEPTED_NIL")
	}
	if transport.config != nativeFenceConfigValid {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_ACCEPTED_NOT_VALID")
	}
	if transport.controlInFD != pipes.controlIn || transport.eventOutFD != pipes.eventOut {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_ACCEPTED_DESCRIPTOR_MISMATCH")
	}
	if !nativeFenceFDReadable(transport.controlInFD) || !nativeFenceFDWritable(transport.eventOutFD) {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_ACCEPTED_DIRECTION_MISMATCH")
	}

	pipes.transfer()
	transport.close()
	if nativeFenceFactoryTestFDOpen(pipes.controlIn) || nativeFenceFactoryTestFDOpen(pipes.eventOut) {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_ACCEPTED_CLEANUP_LEAK")
	}
	transport.close()
	if nativeFenceFactoryTestFDOpen(pipes.controlIn) || nativeFenceFactoryTestFDOpen(pipes.eventOut) {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_ACCEPTED_CLEANUP_NOT_IDEMPOTENT")
	}
}

func TestNativeFenceFactoryClassificationRejection(t *testing.T) {
	t.Run("regular-control", func(t *testing.T) {
		pipes := nativeFenceFactoryNewPipes(t)
		file, err := os.CreateTemp(t.TempDir(), "native-fence-factory-*")
		if err != nil {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_REGULAR_CREATE_FAILED")
		}
		t.Cleanup(func() { _ = file.Close() })
		transport := nativeFenceFactoryFromValues(
			strconv.Itoa(int(file.Fd())), true, strconv.Itoa(pipes.eventOut), true)
		if transport == nil || transport.config != nativeFenceConfigInvalid {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_REGULAR_NOT_INVALID")
		}
		if !nativeFenceFactoryTestFDOpen(int(file.Fd())) || !nativeFenceFactoryTestFDOpen(pipes.eventOut) {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_REGULAR_CLOSED_CALLER_FD")
		}
	})

	t.Run("wrong-direction", func(t *testing.T) {
		pipes := nativeFenceFactoryNewPipes(t)
		transport := nativeFenceFactoryFromValues(
			strconv.Itoa(pipes.controlOut), true, strconv.Itoa(pipes.eventIn), true)
		if transport == nil || transport.config != nativeFenceConfigInvalid {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_WRONG_DIRECTION_NOT_INVALID")
		}
		if !nativeFenceFactoryTestFDOpen(pipes.controlIn) ||
			!nativeFenceFactoryTestFDOpen(pipes.controlOut) ||
			!nativeFenceFactoryTestFDOpen(pipes.eventIn) ||
			!nativeFenceFactoryTestFDOpen(pipes.eventOut) {
			t.Fatal("NATIVE_FENCE_FACTORY_TEST_WRONG_DIRECTION_CLOSED_CALLER_FD")
		}
	})
}

func TestNativeFenceFactorySingletonFreezesSelection(t *testing.T) {
	nativeFenceRunIsolatedChild(t, "factory-singleton", "TestNativeFenceFactorySingletonFreezesSelectionChild")
}

func TestNativeFenceFactorySingletonFreezesSelectionChild(t *testing.T) {
	if os.Getenv(nativeFenceChildCaseEnv) != "factory-singleton" {
		t.Skip("native fence isolated child case only")
	}
	setEnv := nativeFenceFactoryEnvScope(t)

	firstPipes := nativeFenceFactoryNewPipes(t)
	setEnv(strconv.Itoa(firstPipes.controlIn), true, strconv.Itoa(firstPipes.eventOut), true)
	first := nativeInitialUnlockFenceForBuild()
	if first == nil {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_NOT_SELECTED")
	}
	if first.config != nativeFenceConfigValid {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_CONFIG_MISMATCH")
	}
	if first.controlInFD != firstPipes.controlIn || first.eventOutFD != firstPipes.eventOut {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_DESCRIPTOR_MISMATCH")
	}
	firstPipes.transfer()

	secondPipes := nativeFenceFactoryNewPipes(t)
	setEnv(strconv.Itoa(secondPipes.controlIn), true, strconv.Itoa(secondPipes.eventOut), true)
	second := nativeInitialUnlockFenceForBuild()
	if second != first {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_REBOUND")
	}
	if second.controlInFD != firstPipes.controlIn || second.eventOutFD != firstPipes.eventOut {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_DESCRIPTOR_REBOUND")
	}
	if !nativeFenceFactoryTestFDOpen(secondPipes.controlIn) || !nativeFenceFactoryTestFDOpen(secondPipes.eventOut) {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_STOLE_LATER_DESCRIPTOR")
	}

	setEnv("", false, "", false)
	if disabled := nativeInitialUnlockFenceForBuild(); disabled != first {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_DISABLED_ENV_REARMED")
	}

	setEnv("malformed", true, "", false)
	if malformed := nativeInitialUnlockFenceForBuild(); malformed != first {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_INVALID_ENV_REARMED")
	}

	first.close()
	if nativeFenceFactoryTestFDOpen(firstPipes.controlIn) || nativeFenceFactoryTestFDOpen(firstPipes.eventOut) {
		t.Fatal("NATIVE_FENCE_FACTORY_TEST_SINGLETON_CLEANUP_LEAK")
	}
}
