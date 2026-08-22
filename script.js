document.getElementById("myvideo").playbackRate = 0.5;

document.getElementById("inner_box").addEventListener("submit", (e) => {
  e.preventDefault();
  document.getElementById("signup-view").style.display = "none";
  document.getElementById("otp-view").style.display = "flex";
});
    