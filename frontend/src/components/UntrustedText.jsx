// UntrustedText: wraps attacker-controlled text from the log (for example a
// username or user agent) in a dashed amber underline with a warning tooltip.
// It is displayed as plain text only — never interpreted or obeyed.
export const UNTRUSTED_TOOLTIP = 'Typed by an outsider (possibly an attacker). Shown as text only, never trusted or obeyed.'

export default function UntrustedText({ field, children }) {
  return (
    <span
      title={`${field}: ${UNTRUSTED_TOOLTIP}`}
      className="cursor-help rounded-sm bg-amber-400/10 text-amber-100 underline decoration-amber-400/80 decoration-dashed underline-offset-2"
    >
      {children}
    </span>
  )
}

// Small "untrusted" chip, used when a field's exact position couldn't be found.
export function UntrustedTag({ fields }) {
  return (
    <span
      title={`${fields.join(', ')}: ${UNTRUSTED_TOOLTIP}`}
      className="ml-2 inline-block cursor-help rounded border border-amber-400/50 px-1 align-middle font-sans text-[10px] leading-4 text-amber-300 uppercase"
    >
      outsider text
    </span>
  )
}
