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

test('allows ordinary Git calls and non-invocation text', () => {
  const commands = [
    'git status',
    'git status --short',
    'git diff',
    'git diff --cached',
    'git commit -m "save work"',
    'git -C repo status',
    'git -c user.name=dev commit -m save',
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
