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

/**
 * @param {string} password 
 * @returns {HTMLSpanElement[]} div containing the colored password 
 */
export const getColorfulPasswordHTML = (password) =>
  password.split("").map(character => {
    const newSpan = document.createElement("span");
    newSpan.innerText = character;

    if ("a" <= character && character <= "z") newSpan.classList.add("pw-lowercase");
    else if ("A" <= character && character <= "Z") newSpan.classList.add("pw-uppercase");
    else if ("0" <= character && character <= "9") newSpan.classList.add("pw-number");
    else newSpan.classList.add("pw-symbol");

    return newSpan;
  });
