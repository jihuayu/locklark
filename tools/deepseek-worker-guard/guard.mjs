/**
 * Final guard for direct model tool calls that contain an obvious literal
 * `git stash` invocation.
 *
 * This intentionally inspects only the model-facing shell tool names and a
 * string `command`. It is neither a shell parser nor a sandbox.
 */

export const name = 'deepseek-worker-guard'
export const inject = ['tools']

/** A single fixed reason that contains no execution arguments. */
export const DENIAL_REASON = 'Direct Git stash commands are denied by the worker guard.'

const SHELL_TOOL_NAMES = new Set(['bash', 'terminal'])
const GIT_EXECUTABLES = new Set(['git', '/usr/bin/git'])
const SHELL_EXECUTABLES = new Set([
  'bash',
  'sh',
  '/bin/bash',
  '/usr/bin/bash',
  '/bin/sh',
  '/usr/bin/sh',
])
const GIT_FLAGS_WITH_VALUE = new Set(['-C', '-c', '--git-dir', '--work-tree'])
const GIT_FLAGS_WITHOUT_VALUE = new Set(['--no-pager', '--bare'])
const ASSIGNMENT_PREFIX = /^[A-Za-z_][A-Za-z0-9_]*=/
const SHELL_PREFIX_KEYWORDS = new Set([
  '!',
  'do',
  'elif',
  'else',
  'if',
  'then',
  'time',
  'until',
  'while',
])

/**
 * Split shell text at unquoted command separators. This is deliberately a
 * small scanner: enough to see commands after chains and newlines without
 * treating quoted argument text as a command.
 */
function splitShellSegments(command) {
  const segments = []
  let start = 0
  let quote
  let escaped = false

  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]

    if (escaped) {
      escaped = false
      continue
    }

    if (char === '\\' && quote !== "'") {
      escaped = true
      continue
    }

    if (quote !== undefined) {
      if (char === quote) quote = undefined
      continue
    }

    if (char === "'" || char === '"' || char === '`') {
      quote = char
      continue
    }

    if (char === '#' && (index === 0 || /[\s;&|(){}]/.test(command[index - 1]))) {
      const lineEnd = command.indexOf('\n', index)
      if (lineEnd === -1) break
      index = lineEnd - 1
      continue
    }

    if (char === ';' || char === '\n' || char === '&' || char === '|' || char === '(' || char === ')' || char === '{' || char === '}') {
      segments.push(command.slice(start, index))
      start = index + 1
    }
  }

  segments.push(command.slice(start))
  return segments
}

/** Tokenize one shell command segment while removing quoting syntax. */
function tokenizeShellSegment(segment) {
  const tokens = []
  let token = ''
  let started = false
  let quote
  let escaped = false

  for (let index = 0; index < segment.length; index += 1) {
    const char = segment[index]

    if (escaped) {
      token += char
      started = true
      escaped = false
      continue
    }

    if (char === '\\' && quote !== "'") {
      escaped = true
      started = true
      continue
    }

    if (quote !== undefined) {
      if (char === quote) quote = undefined
      else token += char
      started = true
      continue
    }

    if (char === "'" || char === '"') {
      quote = char
      started = true
      continue
    }

    if (/\s/.test(char)) {
      if (started) {
        tokens.push(token)
        token = ''
        started = false
      }
      continue
    }

    token += char
    started = true
  }

  if (started) tokens.push(token)
  return tokens
}

/** Return whether one shell segment is an obvious direct `git stash` call. */
function isGitStashSegment(segment) {
  const tokens = tokenizeShellSegment(segment)
  let index = 0

  while (index < tokens.length) {
    if (ASSIGNMENT_PREFIX.test(tokens[index]) || SHELL_PREFIX_KEYWORDS.has(tokens[index])) {
      index += 1
      continue
    }
    break
  }

  if (GIT_EXECUTABLES.has(tokens[index])) {
    index += 1

    // Skip only the global options this narrow guard is meant to cover.
    while (index < tokens.length) {
      const token = tokens[index]

      if (GIT_FLAGS_WITH_VALUE.has(token)) {
        if (index + 1 >= tokens.length) return false
        index += 2
        continue
      }

      if (GIT_FLAGS_WITHOUT_VALUE.has(token)) {
        index += 1
        continue
      }

      if (token.length > 2 && (token.startsWith('-C') || token.startsWith('-c'))) {
        index += 1
        continue
      }

      if (token.startsWith('--git-dir=') || token.startsWith('--work-tree=')) {
        index += 1
        continue
      }

      break
    }

    return tokens[index] === 'stash'
  }

  // Inspect one literal shell `-c` argument, not arbitrary wrappers.
  if (SHELL_EXECUTABLES.has(tokens[index])) {
    index += 1
    if (tokens[index] !== '-c') return false
    index += 1
    if (index >= tokens.length) return false
    return isGitStashCommand(tokens[index])
  }

  return false
}

/**
 * Pure detector for obvious literal `git stash` command text.
 * @param {unknown} command
 * @returns {boolean}
 */
export function isGitStashCommand(command) {
  if (typeof command !== 'string' || command.length === 0) return false
  return splitShellSegments(command).some(isGitStashSegment)
}

/**
 * Guard callback registered with `ctx.tools.guard()`.
 * @param {{ name?: unknown, arguments?: unknown } | null | undefined} execution
 * @returns {string | undefined}
 */
export function guardExecution(execution) {
  if (execution === null || typeof execution !== 'object') return undefined
  if (!SHELL_TOOL_NAMES.has(execution.name)) return undefined

  const args = execution.arguments
  if (args === null || typeof args !== 'object') return undefined

  const command = args.command
  return isGitStashCommand(command) ? DENIAL_REASON : undefined
}

/** Register the guard with the calling Cordis/DSh tools service. */
export function apply(ctx) {
  ctx.tools.guard(guardExecution)
}

export default { name, inject, apply }
