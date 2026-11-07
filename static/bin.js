/* Bin: press and hold a row to select it, then "Restore selected". */
(function () {
  var rows = document.querySelectorAll(".bin-row");
  if (!rows.length) { return; }
  var bar = document.getElementById("restore-selected");
  var form = document.getElementById("restore-form");
  var timer = null;

  function refresh() {
    var any = document.querySelectorAll(".bin-row.selected").length > 0;
    if (bar) { bar.hidden = !any; }
  }
  function toggle(row) {
    var box = row.querySelector("input[type=checkbox]");
    box.checked = !box.checked;
    row.classList.toggle("selected", box.checked);
    refresh();
  }
  rows.forEach(function (row) {
    var box = row.querySelector("input[type=checkbox]");
    box.addEventListener("change", function () {
      row.classList.toggle("selected", box.checked); refresh();
    });
    function start(event) {
      if (event.target.closest("button, a, input")) { return; }
      timer = setTimeout(function () { toggle(row); timer = null; }, 600);
    }
    function stop() { if (timer) { clearTimeout(timer); timer = null; } }
    row.addEventListener("pointerdown", start);
    ["pointerup", "pointerleave", "pointercancel"].forEach(function (n) { row.addEventListener(n, stop); });
  });
  refresh();
})();