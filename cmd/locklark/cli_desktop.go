package main

import (
	"context"
	"errors"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/personal"
)

// requestCLIRunV2 is the one broker client entry point used by the CLI. It is
// a package variable only so the CLI tests can exercise the provider mapping
// and the post-approval executable recheck without a live desktop process.
var requestCLIRunV2 = browserhost.RequestCLIRunV2

// runCLIBundleWithProvider is the production provider runner. The tests replace
// it to drive the fallback classification with fixed outcomes and no broker or
// temporary-directory assumptions; production always uses the shared personal
// runBundle implementation.
var runCLIBundleWithProvider = personal.RunBundleWithProvider

// newCLIDesktopRunBundleProvider adapts the shared run bundle request into one
// one-shot cli-run v2 exchange with a running desktop broker. The provider sees
// the actual temporary run root created by personal.RunBundleWithProvider and
// forwards the complete public scope: vault, profile name, program, argv,
// directory, timeout, helper PATH, passthrough values and every slot target.
//
// No credential, vault record, snapshot or spec is added by the caller: the
// broker rebuilds the trusted profile from its own built-in registry and binds
// the scope digest to that exact policy. Values returned by the broker are
// owned by the provider result and are zeroed here if the post-approval program
// recheck or any wire step fails.
func newCLIDesktopRunBundleProvider(binding clibinding.ToolBinding) personal.RunBundleProvider {
	return func(ctx context.Context, request personal.RunBundleRequest, targets []personal.BundleTarget, root string) (personal.RunBundleProviderResult, error) {
		params := browserhost.CLIRunV2Params{
			VaultPath:      binding.VaultPath,
			Root:           root,
			ProfileID:      binding.Profile,
			Program:        request.Program,
			Args:           append([]string(nil), request.Args...),
			Directory:      request.Directory,
			TimeoutSeconds: request.TimeoutSeconds,
			HelperPath:     append([]string(nil), request.HelperPath...),
			Passthrough:    cloneCLIDesktopMap(request.Passthrough),
			TokenEnvName:   request.TokenEnvName,
			Targets:        make([]browserhost.CLIRunV2Target, len(targets)),
		}
		for i, target := range targets {
			params.Targets[i] = browserhost.CLIRunV2Target{
				Slot: target.Slot, ID: target.ID, Revision: target.Revision, Field: target.Field,
			}
		}
		result, err := requestCLIRunV2(ctx, params)
		if err != nil {
			clearCLIDesktopValues(result.Values)
			return personal.RunBundleProviderResult{}, err
		}
		// Approval has completed and values may exist. Recheck the pinned
		// executable immediately before those values can reach the child, so a
		// program replaced while the broker prompt was open is refused. The
		// returned bytes are zeroed before the error leaves this provider.
		if err = clibinding.VerifyProgram(binding); err != nil {
			clearCLIDesktopValues(result.Values)
			return personal.RunBundleProviderResult{}, err
		}
		return personal.RunBundleProviderResult{
			Values: result.Values,
			Receipt: personal.RunBundleGrantReceipt{
				Session:      result.Receipt.Session,
				Intent:       result.Receipt.Intent,
				TargetDigest: result.Receipt.TargetDigest,
			},
		}, nil
	}
}

// runCLIBundleWithDesktopOrLocal attempts the desktop provider first and only
// enters the existing local full-factor path for the exact pre-connect
// ErrBrokerUnavailable sentinel. Refused, unknown, context-cancelled, temporary
// and cleanup outcomes are final: RunBundleWithProvider has already zeroed all
// values and removed its temporary root before returning them.
func runCLIBundleWithDesktopOrLocal(ctx context.Context, targets []personal.BundleTarget, request personal.RunBundleRequest, provider personal.RunBundleProvider, local func() error) error {
	receipt, err := runCLIBundleWithProvider(ctx, targets, request, provider)
	if err != nil {
		if errors.Is(err, browserhost.ErrBrokerUnavailable) {
			return local()
		}
		return err
	}
	if receipt.ExitCode != 0 {
		return &childExitStatus{code: receipt.ExitCode}
	}
	return nil
}

func cloneCLIDesktopMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for name, value := range values {
		out[name] = value
	}
	return out
}

func clearCLIDesktopValues(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
	clear(values)
}
