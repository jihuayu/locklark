// Exact native unlock sequence for the external browser acceptance drivers.
// The synthetic factors are entered only after the product's explicit emergency
// input entry is clicked. No label guessing, fallback search or implicit factor
// path is allowed here.

export const EMERGENCY_INPUT_LABEL = "使用应急资料…";

// Fresh locked windows must use the default false. fallbackExpanded is only for
// an existing error-retry window whose emergency panel is already open, where
// the opt-in control is legitimately absent and must not be clicked again.
export function nativeUnlockActions(fixture, { fallbackExpanded = false } = {}) {
  return [
    { click_label: "金库文件" },
    // App.New prefixes DefaultVaultPath, and a pointer click does not select
    // the existing text. Select all before replacing it with the fixture path.
    { key: "Control_L+a" },
    { text: fixture.Path },
    { click_label: "主密码" },
    { text: fixture.Password },
    ...(fallbackExpanded ? [] : [{ click_label: EMERGENCY_INPUT_LABEL }]),
    { click_label: "Secret Key" },
    { text: fixture.Secret },
    { click_label: "解锁" },
  ];
}
