// Plain-English wording for everything technical the backend sends, so the
// dashboard makes sense to someone who has never read a server log.

// What each kind of alert means and what to do about it, keyed by the
// backend's alert title. Unknown titles simply get no explainer.
export const ALERT_EXPLAINERS = {
  'Brute-force login attempts': {
    what: 'Someone kept guessing the password for the same account, over and over, very fast.',
    todo: 'Usually harmless if passwords are strong. Consider blocking this address.',
  },
  'Password spraying across many usernames': {
    what: 'One computer tried to log in to lots of different accounts, hoping one of them has a weak password.',
    todo: 'Make sure no account uses a common password, and consider blocking this address.',
  },
  'Successful login after repeated failures': {
    what: 'After many wrong passwords, someone got in. The attack may have worked.',
    todo: 'Treat this as urgent: change that account’s password and check what it did after logging in.',
  },
  'Login at an unusual hour': {
    what: 'Someone logged in in the middle of the night. It may be normal, or it may be an intruder.',
    todo: 'Ask the account owner whether it was them.',
  },
}

// Friendly progress text for each backend stage (GET /status).
export const STAGE_TEXT = {
  parsing: 'Reading the log file',
  writing_claims: 'The AI is studying each suspicious activity',
  verifying: 'Double-checking every AI statement against the log',
  done: 'Finishing up',
}

// "1 thing" / "3 things".
export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`
}
