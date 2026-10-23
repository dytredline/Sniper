function showGreeting() {
  const params = new URLSearchParams(location.search);
  const who = params.get("name");
  document.getElementById("greet").innerHTML = "Hello " + who; // EXPECT: XSS
  document.getElementById("safe").innerHTML = "<b>static</b>";
  const el = document.querySelector("#out");
  el.textContent = who;
  const fragment = location.hash.slice(1);
  el.insertAdjacentHTML("beforeend", fragment); // EXPECT: XSS
  el.innerHTML = DOMPurify.sanitize(fragment);
  eval(location.hash.substring(1)); // EXPECT: EVAL
}
