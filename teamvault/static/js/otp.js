export async function refreshOtpEvery30Sec(inputElement, secret_url) {
  let secretData, secret, digits, algortihm;
  const response = await fetch(secret_url);
  const data = await response.json();
  secretData = data['otp-key-data']
  secret = secretData["plaintext_key"];
  digits = secretData["digits"];
  algortihm = secretData["algorithm"]; // TODO maybe write own version that consideres algortihm
  const otp = new jsotp.TOTP(secret, digits).now();
  inputElement.value = otp.slice(0, 3) + "·" + otp.slice(3);
}

export function otpCountdown(countdownContainerEl, countdownNumberEl, inputField, secret_url) {
  const unixDict = getUnixTime();
  countdownContainerEl.style.setProperty('--progress', unixDict['countdown']-1);
  countdownNumberEl.textContent = unixDict['countdown']-1;
  if (unixDict['countdown'] === 30) {
    refreshOtpEvery30Sec(inputField, secret_url).then();
  }
}

function getUnixTime(interval = 30) {
  var unixDict = {};
  unixDict['curUnixTime'] = Math.floor(Date.now() / 1000);
  unixDict['intervalStartTime'] = Math.floor(unixDict['curUnixTime'] / 30) * 30;
  unixDict['countdown'] = unixDict['intervalStartTime'] + 30 - unixDict['curUnixTime'];
  return unixDict
}
