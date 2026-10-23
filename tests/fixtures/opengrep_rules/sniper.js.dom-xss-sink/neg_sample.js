function show(msg) {
  const el = document.getElementById('out');
  el.textContent = msg;
  el.innerHTML = '';
  el.innerHTML = DOMPurify.sanitize(msg);
}
