import assert from 'node:assert/strict'
import test from 'node:test'

import guardPlugin, {
  DENIAL_REASON,
  guardExecution,
  isGitStashCommand,
} from './guard.mjs'

function capturePluginGuard() {
  const guards = []
  const ctx = {
    tools: {
      guard(guard) {
        guards.push(guard)
        return () => {}
      },
    },
  }

  guardPlugin.apply(ctx)
  return guards
}

test('plugin registers one monotonic tool guard', () => {
  assert.equal(guardPlugin.name, 'deepseek-worker-guard')
  assert.deepEqual(guardPlugin.inject, ['tools'])
  assert.equal(typeof guardPlugin.apply, 'function')

  const guards = capturePluginGuard()
  assert.equal(guards.length, 1)
  assert.equal(typeof guards[0], 'function')

  assert.equal(
    guards[0]({ name: 'bash', arguments: { command: 'git stash push -m wip' } }),
    DENIAL_REASON,
  )
  assert.equal(
    guards[0]({ name: 'terminal', arguments: { command: 'git stash list' } }),
    DENIAL_REASON,
  )
  assert.equal(
    guards[0]({ name: 'bash', arguments: { command: 'git status --short' } }),
    undefined,
  )
  assert.equal(
    guards[0]({ name: 'python', arguments: { command: 'git stash' } }),
    undefined,
  )
})

test('detects representative literal git stash invocations', () => {
  const commands = [
    'git stash',
    'git stash push -m checkpoint',
    'git stash list',
    '/usr/bin/git stash show --stat',
    'git -C repo stash',
    'git -c user.name=dev stash',
    'git -C /one -c a=b -C /two -c c=d stash apply',
    'git -C/repo -ccore.hooksPath=/dev/null stash',
    'FOO=bar git stash',
    'cd repo && git stash',
    'echo ready\n/usr/bin/git -C /repo stash drop',
    'true; git stash',
    'git diff || git stash',
    'echo x | git stash',
    '(git stash)',
    'if true; then git stash; fi',
  ]

  for (const command of commands) {
    assert.equal(isGitStashCommand(command), true, JSON.stringify(command))
  }
})

test('detects git stash behind the supported global flags', () => {
  const commands = [
    'git --no-pager stash',
    'git --bare stash list',
    'git --git-dir .git stash',
    'git --git-dir=.git stash show',
    'git --work-tree ./wt stash',
    'git --work-tree=./wt stash pop',
    '/usr/bin/git --no-pager stash push',
    'git -C repo --bare stash',
    'git -c user.name=dev --git-dir=.git stash',
    'git --git-dir .git --work-tree ./wt --bare --no-pager stash push',
    'git --work-tree=./wt -Crepo --git-dir=.git -ccore.hooksPath=/dev/null --no-pager stash',
    'git --bare --work-tree ./wt --git-dir .git stash apply',
    'cd repo && git --no-pager stash',
    'echo ready\ngit --git-dir=.git stash drop',
    'true; /usr/bin/git --work-tree=./wt stash',
  ]

  for (const command of commands) {
    assert.equal(isGitStashCommand(command), true, JSON.stringify(command))
  }
})

test('detects a literal shell -c command that directly calls git stash', () => {
  const commands = [
    "bash -c 'git stash push'",
    "sh -c 'git -C repo stash pop'",
    'bash -c "git stash"',
    "/bin/bash -c 'git stash list'",
    "/usr/bin/bash -c 'git --no-pager stash show'",
    "/bin/sh -c 'git stash drop'",
    "/usr/bin/sh -c 'git -c user.name=dev stash'",
    "FOO=bar bash -c 'git stash'",
    "cd repo && sh -c 'git stash'",
    "echo ready\nbash -c 'git stash'",
    "bash -c 'echo ready; git stash'",
    "sh -c 'git status && git --git-dir=.git stash'",
  ]

  for (const command of commands) {
    assert.equal(isGitStashCommand(command), true, JSON.stringify(command))
  }
})

test('allows shell -c text that does not directly call git stash', () => {
  const commands = [
    "bash -c 'echo git stash'",
    "bash -c 'echo \"git stash\"'",
    "bash -c 'printf \"%s\" \"git stash\"'",
    "bash -c 'git status'",
    "sh -c 'git diff --cached'",
    "bash -c 'git commit -m stash'",
    "bash -c 'notgit stash'",
    "bash -c 'git stashless'",
    "bash -c 'echo bash -c git stash'",
    "zsh -c 'git stash'",
    "fish -c 'git stash'",
    "env bash -c 'git stash'",
    "python -c 'git stash'",
    "bash -lc 'git stash'",
    'bash -c',
    "bash -c ''",
  ]

  for (const command of commands) {
    assert.equal(isGitStashCommand(command), false, JSON.stringify(command))
  }
})

test('allows ordinary Git calls and non-invocation text', () => {
  const commands = [
    'git status',
    'git status --short',
    'git diff',
    'git diff --cached',
    'git commit -m "save work"',
    'git -C repo status',
    'git -c user.name=dev commit -m save',
    'git --no-pager status',
    'git --bare diff',
    'git --git-dir .git diff --cached',
    'git --git-dir=.git commit -m "save work"',
    'git --work-tree ./wt status',
    'git --work-tree=./wt commit -m save',
    'git --git-dir',
    'git --work-tree',
    'git --no-pager stashless',
    'git --git-dir=.git stashless',
    'git log --all --grep=stash',
    'git show stash',
    'git stashless',
    'notgit stash',
    '/usr/local/bin/git stash',
    'git -C stash status',
    'echo git stash',
    'echo "git stash"',
    "printf '%s\\n' 'git stash'",
    '# git stash',
  ]

  for (const command of commands) {
    assert.equal(isGitStashCommand(command), false, JSON.stringify(command))
  }
})

test('guard ignores command text on non-shell tool names', () => {
  assert.equal(
    guardExecution({ name: 'python', arguments: { command: 'git stash' } }),
    undefined,
  )
  assert.equal(
    guardExecution({ name: 'read', arguments: { command: 'git stash' } }),
    undefined,
  )
  assert.equal(
    guardExecution({ name: 'bash', arguments: { command: 'git stash' } }),
    DENIAL_REASON,
  )
  assert.equal(
    guardExecution({ name: 'terminal', arguments: { command: 'git stash' } }),
    DENIAL_REASON,
  )
})

test('guard ignores shell literal text on non-shell tool names', () => {
  assert.equal(
    guardExecution({ name: 'python', arguments: { command: "bash -c 'git stash push'" } }),
    undefined,
  )
  assert.equal(
    guardExecution({ name: 'zsh', arguments: { command: "sh -c 'git stash'" } }),
    undefined,
  )
  assert.equal(
    guardExecution({ name: 'read', arguments: { command: "/bin/bash -c 'git stash'" } }),
    undefined,
  )
  assert.equal(
    guardExecution({ name: 'bash', arguments: { command: "bash -c 'git stash push'" } }),
    DENIAL_REASON,
  )
  assert.equal(
    guardExecution({ name: 'terminal', arguments: { command: "sh -c 'git stash'" } }),
    DENIAL_REASON,
  )
})

test('guard tolerates unrelated or missing execution arguments', () => {
  assert.equal(guardExecution(undefined), undefined)
  assert.equal(guardExecution(null), undefined)
  assert.equal(guardExecution({ name: 'bash' }), undefined)
  assert.equal(guardExecution({ name: 'bash', arguments: null }), undefined)
  assert.equal(guardExecution({ name: 'bash', arguments: {} }), undefined)
  assert.equal(guardExecution({ name: 'bash', arguments: { command: 42 } }), undefined)
  assert.equal(guardExecution({ name: 'bash', arguments: { command: 'git status' } }), undefined)
})

test('denial reason is fixed and contains no execution arguments', () => {
  const sentinel = 'UNIQUE_COMMAND_TEXT_9d6f1b3a'
  const command = `git -C /tmp/${sentinel} stash push`

  const firstReason = guardExecution({ name: 'bash', arguments: { command } })
  const secondReason = guardExecution({
    name: 'terminal',
    arguments: { command: 'git stash drop' },
  })

  assert.equal(firstReason, DENIAL_REASON)
  assert.equal(secondReason, DENIAL_REASON)
  assert.equal(firstReason, secondReason)
  assert.equal(firstReason.includes(sentinel), false)
  assert.equal(firstReason.includes(command), false)
  assert.equal(firstReason.includes('/tmp/'), false)
})
