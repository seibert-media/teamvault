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
    bigElement.children[1].innerHTML = newFieldDataBig;
  }
}

export function otpCountdown(countdownContainerEl, countdownNumberEl, inputField, secret_url, bigElement) {
  const unixDict = getUnixTime();
  calcCircleStuff(document.getElementById("progress-circle"), unixDict['countdown']-1)
  countdownContainerEl.style.setProperty('--progress', unixDict['countdown']-1);
  countdownNumberEl.textContent = unixDict['countdown']-1;
  if ( !bigElement.children[0].classList.contains("invisible")) {
    const bigCountdownNumberElement = bigElement.children[0].children[0].children[0];
    const bigCountdownCircleElement = bigElement.children[0].children[0].children[1].children[0];
    bigCountdownNumberElement.textContent = unixDict['countdown']-1;
    bigElement.children[0].children[0].style.setProperty('--progress', unixDict['countdown']-1);
    bigCountdownCircleElement.setAttribute("r", 50)
    bigCountdownCircleElement.setAttribute("cx", 100)
    bigCountdownCircleElement.setAttribute("cy", 100)
    calcCircleStuff(bigCountdownCircleElement, unixDict['countdown']-1)
  }
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


 export function calcCircleStuff(circleElement, progress){
  const radius = circleElement.getAttribute("r");
  const circleSize = (2 * Math.PI) * radius;
  const progressOffset = circleSize - ((progress/30)*circleSize);
  circleElement.style.setProperty("stroke-dasharray", circleSize+'px');
  circleElement.style.setProperty("stroke-dashoffset", progressOffset+'px');
}
