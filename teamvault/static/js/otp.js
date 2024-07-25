export async function refreshOtpEvery30Sec(inputElement, secret_url, bigElement) {
  let secretData, secret, digits, algortihm;
  const response = await fetch(secret_url);
  const data = await response.json();
  secretData = data['otp-key-data']
  secret = secretData["plaintext_key"];
  digits = secretData["digits"];
  // algortihm = secretData["algorithm"]; // TODO maybe write own version that consideres algortihm
  const otp = new jsotp.TOTP(secret, digits).now();
  const newFieldData = otp.slice(0, 3) + " <span class='separator'></span> " + otp.slice(3);
  const newFieldDataBig = otp.slice(0, 3) + "<span class='separator'></span>" + otp.slice(3);
  inputElement.innerHTML = newFieldData;
  if ( !bigElement.classList.contains("invisible")) {
    bigElement.children[0].innerHTML = newFieldDataBig;
  }
}

export function otpCountdown(countdownContainerEl, countdownNumberEl, inputField, secret_url, bigElement) {
  const unixDict = getUnixTime();
  countdownContainerEl.style.setProperty('--progress', unixDict['countdown']-1);
  countdownNumberEl.textContent = unixDict['countdown']-1;
  if (unixDict['countdown'] === 30) {
    refreshOtpEvery30Sec(inputField, secret_url, bigElement).then();
  }
}

function getUnixTime(interval = 30) {
  var unixDict = {};
  unixDict['curUnixTime'] = Math.floor(Date.now() / 1000);
  unixDict['intervalStartTime'] = Math.floor(unixDict['curUnixTime'] / 30) * 30;
  unixDict['countdown'] = unixDict['intervalStartTime'] + 30 - unixDict['curUnixTime'];
  return unixDict
}
