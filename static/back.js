/* The one "Back" link: goes to the page the person came from, or to the
   link's own address when there is none. */
document.addEventListener("click", function (event) {
  var link = event.target.closest("a[data-back]");
  if (!link) { return; }
  var ref = document.referrer;
  if (history.length > 1 && ref && ref.indexOf(location.origin) === 0) {
    event.preventDefault();
    history.back();
  }
});