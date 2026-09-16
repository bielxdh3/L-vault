(() => {
  "use strict";

  const dialog = document.getElementById("media-viewer");
  if (!(dialog instanceof HTMLDialogElement)) return;

  const stage = dialog.querySelector("[data-media-viewer-stage]");
  const title = dialog.querySelector("[data-media-viewer-title]");
  const date = dialog.querySelector("[data-media-viewer-date]");
  const kind = dialog.querySelector("[data-media-viewer-kind]");
  const detailsLink = dialog.querySelector("[data-media-viewer-details]");
  const fileLink = dialog.querySelector("[data-media-viewer-file]");
  const closeButton = dialog.querySelector("[data-media-viewer-close]");
  const shell = dialog.querySelector(".media-dialog-shell");

  if (!stage || !title || !date || !kind || !detailsLink || !fileLink || !closeButton || !shell) return;

  let opener = null;

  function buildMedia(trigger) {
    const type = trigger.dataset.mediaType === "video" ? "video" : "photo";
    const src = trigger.dataset.mediaSrc || "";
    if (!src) return null;

    if (type === "video") {
      const video = document.createElement("video");
      video.controls = true;
      video.preload = "metadata";
      video.playsInline = true;
      const source = document.createElement("source");
      source.src = src;
      video.appendChild(source);
      video.appendChild(document.createTextNode("Este vídeo pode não ser compatível com o navegador."));
      return video;
    }

    const image = document.createElement("img");
    image.src = src;
    image.alt = trigger.dataset.mediaTitle || "Foto";
    image.decoding = "async";
    return image;
  }

  function populate(trigger) {
    const media = buildMedia(trigger);
    if (!media) return false;

    stage.replaceChildren(media);
    title.textContent = trigger.dataset.mediaTitle || "Mídia";
    date.textContent = trigger.dataset.mediaDate || "";
    kind.textContent = trigger.dataset.mediaType === "video" ? "Vídeo" : "Foto";
    detailsLink.href = trigger.dataset.mediaDetails || trigger.href;
    fileLink.href = trigger.dataset.mediaFile || trigger.href;
    return true;
  }

  function openViewer(trigger) {
    if (typeof dialog.showModal !== "function") return false;
    if (!populate(trigger)) return false;

    opener = trigger;
    dialog.showModal();
    document.documentElement.classList.add("media-viewer-open");
    closeButton.focus({ preventScroll: true });
    return true;
  }

  function closeViewer() {
    if (dialog.open) dialog.close();
  }

  document.querySelectorAll("[data-media-viewer-open]").forEach((trigger) => {
    trigger.addEventListener("click", (event) => {
      if (openViewer(trigger)) event.preventDefault();
    });
  });

  closeButton.addEventListener("click", closeViewer);

  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) closeViewer();
  });

  dialog.addEventListener("close", () => {
    const video = stage.querySelector("video");
    if (video) video.pause();
    stage.replaceChildren();
    document.documentElement.classList.remove("media-viewer-open");

    if (opener && opener.isConnected) {
      opener.focus({ preventScroll: true });
    }
    opener = null;
  });

  // Native <dialog> handles Escape via the cancel event. The close event above
  // performs cleanup and restores focus without overriding that browser behavior.
})();
