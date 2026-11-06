/* Upload page only. Shows the chosen files and, once the form is sent,
   a moving "Uploading" bar. The server still checks everything. */
(function () {
  var form = document.getElementById("upload-form");
  if (!form) { return; }
  var input = form.querySelector("input[type=file]");
  var list = document.getElementById("file-list");
  var status = document.getElementById("upload-status");
  var statusText = document.getElementById("upload-status-text");
  var button = form.querySelector("button[type=submit]");

  function size(bytes) {
    if (bytes < 1024) { return bytes + " B"; }
    if (bytes < 1024 * 1024) { return Math.round(bytes / 1024) + " KB"; }
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function showFiles() {
    list.textContent = "";                       // text only, never HTML
    var files = input.files;
    for (var i = 0; i < files.length; i++) {
      var item = document.createElement("li");
      item.textContent = files[i].name + " (" + size(files[i].size) + ")";
      list.appendChild(item);
    }
    list.hidden = files.length === 0;
  }

  function reset() {
    status.hidden = true;
    button.disabled = false;
    button.textContent = "Upload";
  }

  input.addEventListener("change", showFiles);

  form.addEventListener("submit", function () {
    var n = input.files.length;
    statusText.textContent = "Uploading " + n + (n === 1 ? " file" : " files") +
      "… please keep this page open.";
    status.hidden = false;
    button.disabled = true;
    button.textContent = "Uploading…";
  });

  // Coming back with the browser's Back button must not leave the page stuck.
  window.addEventListener("pageshow", reset);
  showFiles();
})();