// Lets ↑ / ↓ / Home / End move focus between the buttons of a list
// (alerts or claims), so the dashboard works without a mouse.
export function moveFocusWithArrows(event, selector) {
  const keys = ['ArrowDown', 'ArrowUp', 'Home', 'End']
  if (!keys.includes(event.key)) return
  const items = [...event.currentTarget.querySelectorAll(selector)]
  if (!items.length) return
  event.preventDefault()
  const i = items.indexOf(document.activeElement)
  const next =
    event.key === 'Home' ? 0
      : event.key === 'End' ? items.length - 1
        : event.key === 'ArrowDown' ? Math.min(i + 1, items.length - 1)
          : Math.max(i - 1, 0)
  items[next].focus()
}
