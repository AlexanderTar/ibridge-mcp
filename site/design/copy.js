// Copy box: <div class="copy-box"><code>…</code><button type="button" aria-label="Copy">…</button></div>
// Copies the code text, shows the copied state for 2 s and announces "Copied" to screen readers.
// A button with an icon (an svg child) keeps its markup and toggles data-copied (the tick shows, no word);
// a text-only button swaps its label between "Copy" and "Copied".
for (const box of document.querySelectorAll(".copy-box")) {
  const button = box.querySelector("button");
  const text = box.querySelector("code").textContent.trim();
  const iconOnly = button.querySelector("svg") !== null;
  const status = document.createElement("span");
  status.className = "visually-hidden";
  status.setAttribute("role", "status");
  box.append(status);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      if (!iconOnly) button.textContent = "Copied";
      button.dataset.copied = "";
      status.textContent = "Copied";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(box.querySelector("code"));
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      status.textContent = "Selected. Press Command-C or Control-C to copy.";
    }
    setTimeout(() => {
      if (!iconOnly) button.textContent = "Copy";
      delete button.dataset.copied;
      status.textContent = "";
    }, 2000);
  });
}
