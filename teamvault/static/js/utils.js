export function scrollIfNeeded(el, containerEl) {
  const rect = el.getBoundingClientRect()
  const containerRect = containerEl.getBoundingClientRect()
  if (rect.top < containerRect.top) {
    if (!(el.previousElementSibling)) {
      el.scrollIntoView({block: 'end'})
    } else {
      el.scrollIntoView({block: 'start'})
    }
  } else if (rect.bottom > containerRect.bottom) {
    if (!(el.nextElementSibling)) {
      el.scrollIntoView({block: 'start'})
    } else {
      el.scrollIntoView({block: 'end'})
    }
  }
}
