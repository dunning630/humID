// Loaded before the app (a plain script, so it runs even if the app bundle
// can't): if HumID fails to start, show why instead of a blank screen.
(function () {
  var shown = false;
  function show(msg) {
    if (shown) return;
    var root = document.getElementById("app");
    if (!root || root.children.length) return;
    shown = true;
    root.innerHTML = "";
    var box = document.createElement("main");
    box.className = "screen boot-error";
    var h = document.createElement("h1"); h.textContent = "HumID couldn't start";
    var p = document.createElement("p"); p.className = "lede"; p.textContent = "Please send this message to HumID support:";
    var pre = document.createElement("pre"); pre.textContent = String(msg || "The app didn't load.");
    var b = document.createElement("button"); b.className = "btn primary block"; b.textContent = "Try again";
    b.onclick = function () { location.reload(); };
    box.appendChild(h); box.appendChild(p); box.appendChild(pre); box.appendChild(b);
    root.appendChild(box);
  }
  window.addEventListener("error", function (e) { show((e.message || "Error") + (e.filename ? " (" + e.filename.split("/").pop() + ":" + e.lineno + ")" : "")); });
  window.addEventListener("unhandledrejection", function (e) { var r = e.reason; if (!document.getElementById("app").children.length) show(r && r.stack ? r.stack.split("\n").slice(0, 3).join("\n") : String(r)); });
  setTimeout(function () { show("The app didn't finish loading after 8 seconds."); }, 8000);
})();
