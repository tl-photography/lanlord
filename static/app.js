"use strict";

const deviceItems = Array.from(document.querySelectorAll(".device-item"));
const desktopPointer = window.matchMedia("(hover: hover) and (pointer: fine)");

function updateDraggable() {
  for (const item of deviceItems) {
    item.draggable = desktopPointer.matches;
  }
}

updateDraggable();
desktopPointer.addEventListener("change", updateDraggable);

document.addEventListener("dragstart", (event) => {
  if (!(event.target instanceof Element)) return;
  const item = event.target.closest(".device-item");
  if (!item || event.target.closest(".move-menu")) {
    event.preventDefault();
    return;
  }
  event.dataTransfer.effectAllowed = "move";
  event.dataTransfer.setData("text/plain", item.dataset.device);
  item.classList.add("dragging");
});

document.addEventListener("dragend", () => {
  for (const item of deviceItems) item.classList.remove("dragging");
  for (const group of document.querySelectorAll(".group.drop-target")) {
    group.classList.remove("drop-target");
  }
});

for (const group of document.querySelectorAll(".group")) {
  group.addEventListener("dragover", (event) => {
    if (!event.dataTransfer.types.includes("text/plain")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    group.classList.add("drop-target");
  });
  group.addEventListener("dragleave", (event) => {
    if (!group.contains(event.relatedTarget)) group.classList.remove("drop-target");
  });
  group.addEventListener("drop", (event) => {
    event.preventDefault();
    group.classList.remove("drop-target");
    const item = deviceItems.find((candidate) => candidate.dataset.device === event.dataTransfer.getData("text/plain"));
    if (!item || item.closest(".group") === group) return;
    const form = Array.from(item.querySelectorAll("form[data-move-group]"))
      .find((candidate) => candidate.dataset.moveGroup === group.dataset.group);
    form?.requestSubmit();
  });
}

let activePointer = null;
let activeCard = null;
let longPressTimer = null;
let longPressedCard = null;
let suppressedClickCard = null;

function cancelLongPress() {
  window.clearTimeout(longPressTimer);
  activePointer = null;
  activeCard = null;
}

document.addEventListener("pointerdown", (event) => {
  if (!(event.target instanceof Element) || event.pointerType === "mouse") return;
  const card = event.target.closest(".device-item .card");
  if (!card) return;
  cancelLongPress();
  suppressedClickCard = null;
  longPressedCard = null;
  activePointer = { id: event.pointerId, x: event.clientX, y: event.clientY };
  activeCard = card;
  longPressTimer = window.setTimeout(() => {
    const menu = activeCard?.parentElement.querySelector(".move-menu");
    if (!menu) return;
    menu.open = true;
    menu.querySelector("summary")?.focus({ preventScroll: true });
    longPressedCard = activeCard;
  }, 500);
});

document.addEventListener("pointermove", (event) => {
  if (!activePointer || event.pointerId !== activePointer.id) return;
  if (Math.hypot(event.clientX - activePointer.x, event.clientY - activePointer.y) > 10) cancelLongPress();
});

document.addEventListener("pointerup", (event) => {
  if (!activePointer || event.pointerId !== activePointer.id) return;
  if (longPressedCard === activeCard) suppressedClickCard = activeCard;
  cancelLongPress();
});

document.addEventListener("pointercancel", cancelLongPress);
document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element) || !suppressedClickCard?.contains(event.target)) return;
  event.preventDefault();
  event.stopPropagation();
  suppressedClickCard = null;
}, true);

for (const form of document.querySelectorAll(".plugin-toggle")) {
  form.querySelector('input[name="enabled"]')?.addEventListener("change", () => form.requestSubmit());
}

const pluginSearch = document.querySelector("#plugin-search");
pluginSearch?.addEventListener("input", () => {
  const query = pluginSearch.value.trim().toLowerCase();
  for (const plugin of document.querySelectorAll(".plugin-entry")) {
    plugin.hidden = !plugin.dataset.search.includes(query);
  }
});