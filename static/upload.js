/* Upload page: lists the chosen files and shows a real progress bar with a
   percentage. The server still checks everything. */
(function () {
  var form = document.getElementById("upload-form");
  if (!form) { return; }
  var input = form.querySelector("input[type=file]");
  var list = document.getElementById("file-list");
  var status = document.getElementById("upload-status");
  var statusText = document.getElementById("upload-status-text");
  var fill = status.querySelector(".upload-bar span");
  var button = form.querySelector("button[type=submit]");
  var errorBox = document.getElementById("upload-error");
  var LIMIT = 100 * 1024 * 1024;

  function size(bytes) {
    if (bytes < 1024) { return bytes + " B"; }
    if (bytes < 1024 * 1024) { return Math.round(bytes / 1024) + " KB"; }
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }
  function total() {
    var sum = 0;
    for (var i = 0; i < input.files.length; i++) { sum += input.files[i].size; }
    return sum;
  }
  function showFiles() {
    list.textContent = "";                       // text only, never HTML
    for (var i = 0; i < input.files.length; i++) {
      var item = document.createElement("li");
      item.textContent = input.files[i].name + " (" + size(input.files[i].size) + ")";
      list.appendChild(item);
    }
    list.hidden = input.files.length === 0;
  }
  function fail(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
    status.hidden = true;
    button.disabled = false;
    button.textContent = "Upload";
  }

  input.addEventListener("change", showFiles);

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    errorBox.hidden = true;
    if (total() > LIMIT) { fail("These files are more than 100 MB together. Choose fewer files."); return; }
    var xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
    xhr.upload.addEventListener("progress", function (e) {
      if (!e.lengthComputable) { return; }
      var pct = Math.round(e.loaded * 100 / e.total);
      fill.style.width = pct + "%";               // allowed by the page policy (not an inline attribute)
      statusText.textContent = "Uploading… " + pct + "%";
    });
    xhr.addEventListener("load", function () {
      var reply = {};
      try { reply = JSON.parse(xhr.responseText); } catch (e) { reply = {}; }
      if (xhr.status === 200 && reply.redirect) {
        fill.style.width = "100%";
        statusText.textContent = "Done. Opening your documents…";
        window.location = reply.redirect;
      } else {
        fail(reply.error || (xhr.status === 413 ? "That upload is too large (100 MB in total)." : "The upload failed. Please try again."));
      }
    });
    xhr.addEventListener("error", function () { fail("The upload could not be sent. Check your connection and try again."); });
    fill.style.width = "0%";
    statusText.textContent = "Uploading… 0%";
    status.hidden = false;
    button.disabled = true;
    button.textContent = "Uploading…";
    xhr.send(new FormData(form));
  });

  window.addEventListener("pageshow", function () { status.hidden = true; button.disabled = false; button.textContent = "Upload"; });
  showFiles();
})();