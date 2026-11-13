import assert from 'node:assert/strict'
import test from 'node:test'

import guardPlugin, {
  DENIAL_REASON,
  SENSITIVE_PATH_DENIAL_REASON,
  guardExecution,
  isGitStashCommand,
  mentionsSensitivePath,
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

// ---------------------------------------------------------------------------
// Sensitive-path guard. Every path below is synthetic (`/tmp/fake-home`,
// `example.invalid`); no file is read or resolved and no command is run.
// ---------------------------------------------------------------------------

const CREDENTIAL_SUFFIX = ['.config', 'deepseek-subagent', 'credentials.json'].join('/')
const QUARANTINE_NAME = ['sensitive', 'quarantine'].join('-')
const SERVERLAB = ['serverlab', 'psql'].join('.')
const SERVERLAB_PREFIX = ['not', 'serverlab'].join('')
const FAKE_HOME = '/tmp/fake-home'
const CREDENTIAL_TILDE = '~/' + CREDENTIAL_SUFFIX
const CREDENTIAL_ABSOLUTE = FAKE_HOME + '/' + CREDENTIAL_SUFFIX
const QUARANTINE_PATH = '/tmp/fake-work/' + QUARANTINE_NAME + '/item.txt'
const SERVERLAB_PATH = '/tmp/fake-work/' + SERVERLAB
const QUARANTINE_RELATIVE = QUARANTINE_NAME + '/item.txt'
const SERVERLAB_RELATIVE = 'fake-work/' + SERVERLAB
// Synthetic bare relative names only; never a real path.
const QUARANTINE_ITEM = 'item.txt'
const CASE_PATHS = [
  [CREDENTIAL_SUFFIX, CREDENTIAL_SUFFIX.toUpperCase()],
  [QUARANTINE_RELATIVE, QUARANTINE_RELATIVE.toUpperCase()],
  [SERVERLAB_RELATIVE, SERVERLAB_RELATIVE.toUpperCase()],
]

/** Build a synthetic mixed-case variant without touching any real path. */
function toAlternatingCase(text) {
  let out = ''
  for (let index = 0; index < text.length; index += 1) {
    out += index % 2 === 0 ? text[index].toLowerCase() : text[index].toUpperCase()
  }
  return out
}

function deniedSensitive(execution) {
  return guardExecution(execution) === SENSITIVE_PATH_DENIAL_REASON
}

test('sensitive path denial reason is fixed and mentions no path or filename', () => {
  assert.equal(typeof SENSITIVE_PATH_DENIAL_REASON, 'string')
  assert.notEqual(SENSITIVE_PATH_DENIAL_REASON, '')
  assert.notEqual(SENSITIVE_PATH_DENIAL_REASON, DENIAL_REASON)
  for (const fragment of [
    'credentials',
    '.json',
    'deepseek-subagent',
    '.config',
    QUARANTINE_NAME,
    SERVERLAB,
    FAKE_HOME,
    '~',
    '/',
  ]) {
    assert.equal(SENSITIVE_PATH_DENIAL_REASON.includes(fragment), false, fragment)
  }
})

test('detects the literal sensitive path forms', () => {
  const texts = [
    CREDENTIAL_TILDE,
    CREDENTIAL_ABSOLUTE,
    '/Users/fake-home/' + CREDENTIAL_SUFFIX,
    QUARANTINE_PATH,
    '/tmp/fake-work/' + SERVERLAB,
    SERVERLAB_PATH + ':12',
  ]
  for (const text of texts) {
    assert.equal(mentionsSensitivePath(text), true, JSON.stringify(text))
  }
})

test('detects quoted relative sensitive paths as separate tokens', () => {
  const texts = [
    CREDENTIAL_SUFFIX,
    '"' + CREDENTIAL_SUFFIX + '"',
    QUARANTINE_RELATIVE,
    "'" + QUARANTINE_RELATIVE + "'",
    SERVERLAB_RELATIVE,
    '"' + SERVERLAB_RELATIVE + '"',
  ]
  for (const text of texts) {
    assert.equal(mentionsSensitivePath(text), true, JSON.stringify(text))
  }
})

test('denies quoted relative sensitive path commands', () => {
  const commands = [
    'cat "' + CREDENTIAL_SUFFIX + '"',
    "cat '" + QUARANTINE_RELATIVE + "'",
    'sed -n 1p "' + SERVERLAB_RELATIVE + '"',
  ]
  for (const command of commands) {
    assert.equal(
      deniedSensitive({ name: 'bash', arguments: { command } }),
      true,
      JSON.stringify(command),
    )
  }
})

test('detects case variants of every protected path spelling', () => {
  for (const [lower, upper] of CASE_PATHS) {
    for (const variant of [upper, toAlternatingCase(lower)]) {
      for (const text of [variant, FAKE_HOME + '/' + variant, '"' + variant + '"']) {
        assert.equal(mentionsSensitivePath(text), true, JSON.stringify(text))
      }
    }
  }
})

test('allows case variants of near-miss path text', () => {
  // Built from mixed-case host and suffix segments, so near-miss text still
  // exercises case variants without embedding a protected spelling.
  const exactHost = toAlternatingCase(SERVERLAB)
  const notHost = toAlternatingCase(SERVERLAB_PREFIX + SERVERLAB)
  const credentialHost = ['Deepseek', 'Subagent'].map(toAlternatingCase)
  const texts = [
    toAlternatingCase(CREDENTIAL_TILDE) + '.BaK',
    toAlternatingCase(CREDENTIAL_ABSOLUTE) + '.TmP',
    '~/.ConFig/' + credentialHost[0] + '/credentials.jsonx',
    '/tmp/' + QUARANTINE_NAME.toUpperCase() + '-Old/x.txt',
    '"' + QUARANTINE_NAME.toUpperCase() + '-Old/x.txt"',
    QUARANTINE_NAME.toUpperCase() + '-Old/' + QUARANTINE_ITEM,
    notHost + '.Psql',
    exactHost + '.PsqlX',
    exactHost + '.Psql.BaK',
    '/tmp/' + notHost + '.Psql',
  ]
  for (const text of texts) {
    assert.equal(mentionsSensitivePath(text), false, JSON.stringify(text))
  }
})

test('allows near-miss and unrelated path text', () => {
  const texts = [
    '',
    '~/.config/deepseek-subagent/credentials.json.bak',
    '~/.config/deepseek-subagent/credentials.json.tmp',
    FAKE_HOME + '/.config/other/credentials.json',
    FAKE_HOME + '/.config/deepseek-subagent/settings.json',
    '~/.config/deepseek-subagentx/' + 'credentials.json',
    '/tmp/fake-work/' + QUARANTINE_NAME + '-old/item.txt',
    '/tmp/fake-work/' + SERVERLAB + '.bak',
    '/tmp/fake-work/' + SERVERLAB + 'x',
    '/tmp/fake-work/' + SERVERLAB + '.psql',
    '/tmp/fake-work/' + 'serverlab',
    '/tmp/fake-work/ordinary.txt',
    'credentials.json',
    'git status',
  ]
  for (const text of texts) {
    assert.equal(mentionsSensitivePath(text), false, JSON.stringify(text))
  }
  assert.equal(mentionsSensitivePath(42), false)
  assert.equal(mentionsSensitivePath(undefined), false)
})

test('denies direct read and read_image file_path arguments', () => {
  for (const name of ['read', 'read_image']) {
    for (const filePath of [CREDENTIAL_TILDE, CREDENTIAL_ABSOLUTE, QUARANTINE_PATH, SERVERLAB_PATH]) {
      assert.equal(deniedSensitive({ name, arguments: { file_path: filePath } }), true, name + ' ' + filePath)
    }
    assert.equal(
      deniedSensitive({ name, arguments: { file_path: QUARANTINE_PATH + '/nested.png' } }),
      true,
    )
  }
})

test('allows ordinary file_path arguments on read tools', () => {
  for (const name of ['read', 'read_image']) {
    assert.equal(guardExecution({ name, arguments: { file_path: '/tmp/fake-work/README.md' } }), undefined)
    assert.equal(guardExecution({ name, arguments: {} }), undefined)
    assert.equal(guardExecution({ name, arguments: { file_path: 7 } }), undefined)
    assert.equal(guardExecution({ name, arguments: { file_path: FAKE_HOME + '/.config/other/credentials.json' } }), undefined)
  }
})

test('denies literal shell commands naming a sensitive path in direct forms', () => {
  const commands = [
    'cat ' + CREDENTIAL_TILDE,
    'cat "' + CREDENTIAL_ABSOLUTE + '"',
    'sed -n 1,5p ' + CREDENTIAL_ABSOLUTE,
    "python3 -c 'print(\"" + FAKE_HOME + '/' + CREDENTIAL_SUFFIX + "\")'",
    'cat ' + QUARANTINE_PATH,
    'cd /tmp && sed -n 1p ' + QUARANTINE_PATH,
    "python -c 'open(\"" + QUARANTINE_PATH + "\").read()'",
    'cat ' + SERVERLAB_PATH,
    'ls /tmp/fake-work\ncat ' + SERVERLAB_PATH,
    "python3 - <<'PY'\nopen('" + SERVERLAB_PATH + "').read()\nPY",
    "bash -c 'cat " + SERVERLAB_PATH + "'",
  ]
  for (const name of ['bash', 'terminal']) {
    for (const command of commands) {
      assert.equal(deniedSensitive({ name, arguments: { command } }), true, name + ' ' + JSON.stringify(command))
    }
  }
})

test('allows shell commands without a literal sensitive path', () => {
  const commands = [
    'cat /tmp/fake-work/README.md',
    'sed -n 1p /tmp/fake-work/' + SERVERLAB + '.bak',
    'python3 -c "print(1)"',
    'git status --short',
    'echo credentials',
  ]
  for (const command of commands) {
    assert.equal(guardExecution({ name: 'bash', arguments: { command } }), undefined, JSON.stringify(command))
  }
})

test('stash denial takes precedence and stash behavior is preserved', () => {
  assert.equal(
    guardExecution({ name: 'bash', arguments: { command: 'git stash && cat ' + SERVERLAB_PATH } }),
    DENIAL_REASON,
  )
  assert.equal(isGitStashCommand('git stash'), true)
  assert.equal(
    guardExecution({ name: 'read', arguments: { file_path: SERVERLAB_PATH, command: 'git stash' } }),
    SENSITIVE_PATH_DENIAL_REASON,
  )
})

test('sensitive path guard ignores other tool names and unrelated argument keys', () => {
  for (const name of ['python', 'zsh', 'grep', 'web_fetch', 'write']) {
    assert.equal(guardExecution({ name, arguments: { command: 'cat ' + SERVERLAB_PATH } }), undefined, name)
    assert.equal(guardExecution({ name, arguments: { file_path: SERVERLAB_PATH } }), undefined, name)
  }
  assert.equal(
    guardExecution({ name: 'bash', arguments: { description: 'read ' + SERVERLAB_PATH } }),
    undefined,
  )
  assert.equal(
    guardExecution({ name: 'read', arguments: { command: SERVERLAB_PATH } }),
    undefined,
  )
})

test('sensitive path guard tolerates malformed executions', () => {
  assert.equal(guardExecution(undefined), undefined)
  assert.equal(guardExecution(null), undefined)
  assert.equal(guardExecution({ name: 'read' }), undefined)
  assert.equal(guardExecution({ name: 'read', arguments: null }), undefined)
  assert.equal(guardExecution({ name: 'read', arguments: [] }), undefined)
  assert.equal(
    guardExecution({ name: 'bash', arguments: Object.assign([], { command: SERVERLAB_PATH }) }),
    undefined,
  )
})

test('recursive scan covers nested array/object path values on covered tools', () => {
  for (const name of ['bash', 'terminal']) {
    assert.equal(deniedSensitive({ name, arguments: { command: ['cat ' + SERVERLAB_PATH] } }), true, name)
    assert.equal(
      deniedSensitive({ name, arguments: { command: ['echo ok', 'cat ' + QUARANTINE_PATH] } }),
      true,
      name,
    )
    assert.equal(
      deniedSensitive({ name, arguments: { script: [{ chunk: CREDENTIAL_TILDE }] } }),
      true,
      name,
    )
    assert.equal(
      guardExecution({ name, arguments: { command: ['cat /tmp/fake-work/README.md'] } }),
      undefined,
      name,
    )
  }
  assert.equal(
    deniedSensitive({ name: 'read', arguments: { file_path: [{ path: SERVERLAB_PATH }] } }),
    true,
  )
})

test('sensitive path denial never echoes the execution arguments', () => {
  const sentinel = 'UNIQUE_PATH_TEXT_4c1e7d2b'
  const filePath = '/tmp/fake-work/' + sentinel + '/' + QUARANTINE_NAME + '/x'
  const reason = guardExecution({ name: 'read', arguments: { file_path: filePath } })
  assert.equal(reason, SENSITIVE_PATH_DENIAL_REASON)
  assert.equal(reason.includes(sentinel), false)
  assert.equal(reason.includes(filePath), false)
  assert.equal(guardExecution({ name: 'bash', arguments: { command: 'cat ' + filePath } }), SENSITIVE_PATH_DENIAL_REASON)
})
