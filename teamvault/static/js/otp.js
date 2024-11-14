export async function refreshOtpEvery30Sec(inputElement, secret_url, bigElement) {
  const response = await fetch(secret_url+"/otp");
  const otp = await response.json();
  let newFieldData = otp.slice(0, 3) + "<span class='separator mx-1'></span>" + otp.slice(3);
  inputElement.innerHTML = newFieldData;
  if ( !bigElement.classList.contains("invisible")) {
    bigElement.children[1].innerHTML = newFieldData.replace('mx-1', 'mx-3');
  }
}

export async function otpCountdown(countdownContainerEl, countdownNumberEl, inputField, secret_url, bigElement) {
  const countdownTime = getcountdownTime();
  setCircleParams(document.getElementById("progress-circle"), countdownTime);
  countdownContainerEl.style.setProperty('--progress', countdownTime);
  countdownNumberEl.textContent = countdownTime;
  if ( !bigElement.children[0].classList.contains("invisible")) {
    const bigCountdownElement = bigElement.children[0].children[0];
    const bigCountdownNumberElement = bigCountdownElement.children[0];
    const bigCountdownCircleElement = bigCountdownElement.children[1].children[0];
    bigCountdownNumberElement.textContent = countdownTime;
    bigCountdownElement.style.setProperty('--progress', countdownTime);
    bigCountdownCircleElement.setAttribute("r", 50);
    bigCountdownCircleElement.setAttribute("cx", 100);
    bigCountdownCircleElement.setAttribute("cy", 100);
    setCircleParams(bigCountdownCircleElement, countdownTime);
  }
  if (countdownTime+1 === 30) {
    await refreshOtpEvery30Sec(inputField, secret_url, bigElement).then();
  }
}

function getcountdownTime(interval = 30) {
  const curUnixTime = Math.floor(Date.now() / 1000);
  const intervalStartTime = Math.floor(curUnixTime / 30) * 30;
  return intervalStartTime + 30 - curUnixTime - 1;
}


function setCircleParams(circleElement, progress){
  const radius = circleElement.getAttribute("r");
  const circleSize = (2 * Math.PI) * radius;
  const progressOffset = circleSize - ((progress/30)*circleSize);
  circleElement.style.setProperty("stroke-dasharray", circleSize+'px');
  circleElement.style.setProperty("stroke-dashoffset", progressOffset+'px');
}
