// Sanity checks on a report from the backend. ProofLog's promise is that every
// claim is backed by real log lines, so the dashboard double-checks the report
// itself instead of trusting it blindly. Problems are listed on screen and in the PDF.
//
// Returns:
//   trust    - trust score recounted from the claims' own `verified` flags
//   warnings - plain-English problems found (empty if the report looks consistent)
export function checkReportIntegrity(report) {
  const warnings = []
  const { alerts, claims, log_lines: lines, trust_score: reported } = report

  const lineNumbers = new Set(lines.map((l) => l.line))
  const alertIds = new Set(alerts.map((a) => a.id))

  // Trust score: count it ourselves.
  const trust = { verified: claims.filter((c) => c.verified === true).length, total: claims.length }
  if (reported?.verified !== trust.verified || reported?.total !== trust.total) {
    warnings.push(
      `The backend reported ${reported?.verified} of ${reported?.total} claims verified, but the claims themselves say ${trust.verified} of ${trust.total}. Showing the recounted score.`,
    )
  }

  // Line numbering.
  if (lines.some((l) => l.line === 0)) {
    warnings.push('Log lines are numbered from 0 instead of 1. Evidence highlights may be off by one line.')
  }
  const dupLines = duplicates(lines.map((l) => l.line))
  if (dupLines.length) warnings.push(`Duplicate log line numbers: ${listOf(dupLines)}.`)

  // Evidence must point at real lines, and every claim needs some.
  const badRefs = claims
    .map((c) => ({ id: c.id, missing: c.evidence_lines.filter((n) => !lineNumbers.has(n)) }))
    .filter((c) => c.missing.length)
  if (badRefs.length) {
    warnings.push(
      `Evidence points to lines that are not in the log: ${badRefs.map((c) => `claim ${c.id} → line ${listOf(c.missing)}`).join('; ')}.`,
    )
  }
  const noEvidence = claims.filter((c) => c.evidence_lines.length === 0).map((c) => c.id)
  if (noEvidence.length) warnings.push(`Claims with no evidence lines: ${listOf(noEvidence)}.`)

  // IDs must be unique and claims must belong to a real alert.
  const dupAlerts = duplicates(alerts.map((a) => a.id))
  if (dupAlerts.length) warnings.push(`Duplicate alert ids: ${listOf(dupAlerts)}. Selecting these alerts may misbehave.`)
  const dupClaims = duplicates(claims.map((c) => c.id))
  if (dupClaims.length) warnings.push(`Duplicate claim ids: ${listOf(dupClaims)}. Selecting these claims may misbehave.`)
  const orphans = claims.filter((c) => !alertIds.has(c.alert_id)).map((c) => c.id)
  if (orphans.length) warnings.push(`Claims linked to an alert that doesn't exist (not shown): ${listOf(orphans)}.`)

  return { trust, warnings }
}

function duplicates(values) {
  const seen = new Set()
  return [...new Set(values.filter((v) => seen.has(v) || !seen.add(v)))]
}

function listOf(values) {
  const shown = values.slice(0, 8).join(', ')
  return values.length > 8 ? `${shown} and ${values.length - 8} more` : shown
}
