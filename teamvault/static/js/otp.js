export async function refreshOtpEvery30Sec(inputElement, secret_url, bigElement) {
  let secretData, secret, digits, algortihm;
  const response = await fetch(secret_url);
  const data = await response.json();
  secretData = data['otp-key-data'];
  secret = secretData["plaintext_key"];
  digits = secretData["digits"];
  algortihm = secretData["algorithm"]; // TODO maybe write own version that consideres algortihm
  const otp = new jsotp.TOTP(secret, digits).now();
  const newFieldData = otp.slice(0, 3) + " <span class='separator'></span> " + otp.slice(3);
  const newFieldDataBig = otp.slice(0, 3) + "<span class='separator'></span>" + otp.slice(3); // without spaces between separator and OTP
  inputElement.innerHTML = newFieldData;
  if ( !bigElement.classList.contains("invisible")) {
    bigElement.children[1].innerHTML = newFieldDataBig;
  }
}

export function otpCountdown(countdownContainerEl, countdownNumberEl, inputField, secret_url, bigElement) {
  const countdowmTime = getCountdowmTime();
  setCircleParams(document.getElementById("progress-circle"), countdowmTime);
  countdownContainerEl.style.setProperty('--progress', countdowmTime);
  countdownNumberEl.textContent = countdowmTime;
  if ( !bigElement.children[0].classList.contains("invisible")) {
    const bigCountdownElement = bigElement.children[0].children[0];
    const bigCountdownNumberElement = bigCountdownElement.children[0];
    const bigCountdownCircleElement = bigCountdownElement.children[1].children[0];
    bigCountdownNumberElement.textContent = countdowmTime;
    bigCountdownElement.style.setProperty('--progress', countdowmTime);
    bigCountdownCircleElement.setAttribute("r", 50);
    bigCountdownCircleElement.setAttribute("cx", 100);
    bigCountdownCircleElement.setAttribute("cy", 100);
    setCircleParams(bigCountdownCircleElement, countdowmTime);
  }
  if (countdowmTime+1 === 30) {
    refreshOtpEvery30Sec(inputField, secret_url, bigElement).then();
  }
}

function getCountdowmTime(interval = 30) {
  const curUnixTime = Math.floor(Date.now() / 1000);
  const intervalStartTime = Math.floor(curUnixTime / 30) * 30;
  return intervalStartTime + 30 - curUnixTime - 1;
}


 export function setCircleParams(circleElement, progress){
  const radius = circleElement.getAttribute("r");
  const circleSize = (2 * Math.PI) * radius;
  const progressOffset = circleSize - ((progress/30)*circleSize);
  circleElement.style.setProperty("stroke-dasharray", circleSize+'px');
  circleElement.style.setProperty("stroke-dashoffset", progressOffset+'px');
}
