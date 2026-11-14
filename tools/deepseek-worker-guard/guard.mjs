/**
 * Final guard for direct model tool calls that contain an obvious literal
 * `git stash` invocation, or that directly read a small fixed set of local
 * sensitive path forms.
 *
 * This intentionally inspects model-facing tool names and string arguments
 * only. It is neither a shell/Python parser nor a filesystem sandbox: it only
 * matches literal path text, so computed paths and indirect code are out of
 * scope.
 */

export const name = 'deepseek-worker-guard'
export const inject = ['tools']

/** A single fixed reason that contains no execution arguments. */
export const DENIAL_REASON = 'Direct Git stash commands are denied by the worker guard.'

/** A single fixed sensitive-path reason that contains no paths or filenames. */
export const SENSITIVE_PATH_DENIAL_REASON =
  'Direct reads of local sensitive paths are denied by the worker guard.'

/**
 * Tool names whose direct path argument is `file_path`. Other arguments of
 * these tools are not path literals and are not inspected.
 */
const FILE_PATH_TOOL_NAMES = new Set(['read', 'read_image'])

/** Per-tool argument fields scanned for literal sensitive path text. */
const FILE_PATH_ARGUMENT_KEYS = new Set(['file_path', 'path', 'paths'])
const SHELL_ARGUMENT_KEYS = new Set(['command', 'cmd', 'script'])

/** A path boundary: start of text, whitespace, or a literal shell quote. */
const RELATIVE_START = String.raw`(?:^|\s|["'])`
/** The end of a quoted relative path is its closing quote or end of text. */
const QUOTED_END = String.raw`(?=["']|$)`
/** Optional leading separator for path-bearing forms (absolute or `~/`). */
const PATH_START = String.raw`(?:^|[/\\~])`

/**
 * Literal sensitive path forms. The credential path literal must end the
 * path: it is followed by a delimiter or the end of the scanned string, so
 * longer names such as `credentials.json.bak` do not match. Matching is
 * case-insensitive because the host filesystem may be case-insensitive.
 * Shell token boundaries leave a `cat ".config/...json"` command tokenizable.
 */
const CREDENTIAL_LITERAL = String.raw`\.config[/\\]deepseek-subagent[/\\]credentials\.json`

/**
 * Literal sensitive path forms, each as a quoted relative path
 * (a `.config/...`-style relative path as its own shell token)
 * or as an absolute / `~/` path anywhere in the scanned text.
 */
const SENSITIVE_PATH_PATTERNS = [
  new RegExp(String.raw`${CREDENTIAL_LITERAL}(?=$|[^\w.-])|${RELATIVE_START}${CREDENTIAL_LITERAL}${QUOTED_END}`, 'i'),
  new RegExp(String.raw`${PATH_START}sensitive-quarantine(?=$|[/\\])|${RELATIVE_START}sensitive-quarantine[/\\][^"'*?\n]*${QUOTED_END}`, 'i'),
  new RegExp(String.raw`serverlab\.psql(?=$|[^\w.-])|${RELATIVE_START}serverlab\.psql${QUOTED_END}`, 'i'),
]

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
 * Pure detector for literal text mentioning one of the fixed sensitive path
 * forms. Lexical only: it neither resolves `~`, reads HOME, nor touches disk.
 * @param {unknown} text
 * @returns {boolean}
 */
export function mentionsSensitivePath(text) {
  if (typeof text !== 'string' || text.length === 0) return false
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(text))
}

/**
 * Walk JSON-shaped argument values recursively and test only their string
 * values against the sensitive path patterns.
 * @param {unknown} value
 * @returns {boolean}
 */
function hasSensitivePathValue(value) {
  if (typeof value === 'string') return mentionsSensitivePath(value)
  if (Array.isArray(value)) return value.some(hasSensitivePathValue)
  if (value !== null && typeof value === 'object') {
    return Object.values(value).some(hasSensitivePathValue)
  }
  return false
}

/** Return only the selected argument fields of one tool call. */
function scannedArguments(args, keys) {
  return Object.entries(args)
    .filter(([key]) => keys.has(key))
    .map(([, value]) => value)
}

/**
 * Guard callback registered with `ctx.tools.guard()`.
 * @param {{ name?: unknown, arguments?: unknown } | null | undefined} execution
 * @returns {string | undefined}
 */
export function guardExecution(execution) {
  if (execution === null || typeof execution !== 'object') return undefined

  const args = execution.arguments
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return undefined

  if (SHELL_TOOL_NAMES.has(execution.name)) {
    const stashCommand = args.command
    if (isGitStashCommand(stashCommand)) return DENIAL_REASON
    if (scannedArguments(args, SHELL_ARGUMENT_KEYS).some(hasSensitivePathValue)) {
      return SENSITIVE_PATH_DENIAL_REASON
    }
    return undefined
  }

  if (FILE_PATH_TOOL_NAMES.has(execution.name)) {
    if (scannedArguments(args, FILE_PATH_ARGUMENT_KEYS).some(hasSensitivePathValue)) {
      return SENSITIVE_PATH_DENIAL_REASON
    }
    return undefined
  }

  return undefined
}

/** Register the guard with the calling Cordis/DSh tools service. */
export function apply(ctx) {
  ctx.tools.guard(guardExecution)
}

export default { name, inject, apply }
