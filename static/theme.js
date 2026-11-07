/* Light or dark. Loaded in the page head so there is no flash of the wrong
   colours. The choice is kept in this browser only. */
(function () {
  var root = document.documentElement;
  var stored = null;
  try { stored = localStorage.getItem("tv-theme"); } catch (e) { stored = null; }
  var dark = stored ? stored === "dark"
    : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  root.setAttribute("data-theme", dark ? "dark" : "light");

  document.addEventListener("DOMContentLoaded", function () {
    var buttons = document.querySelectorAll("[data-theme-choice]");
    function mark() {
      var current = root.getAttribute("data-theme");
      buttons.forEach(function (b) {
        b.setAttribute("aria-pressed", String(b.getAttribute("data-theme-choice") === current));
      });
    }
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        var choice = b.getAttribute("data-theme-choice");
        root.setAttribute("data-theme", choice);
        try { localStorage.setItem("tv-theme", choice); } catch (e) { /* not saved */ }
        mark();
      });
    });
    mark();
  });
})();