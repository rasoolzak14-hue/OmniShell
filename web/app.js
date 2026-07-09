// Mirrors the search/synonym logic in src/engine.cpp so the website and
// the C++ app behave the same way against the same data/*.json files.

const DATA_DIR = "data/";

const providerSelect = document.getElementById("provider-select");
const providerView = document.getElementById("provider-view");
const providerTitle = document.getElementById("provider-title");
const searchInput = document.getElementById("search-input");
const resultCount = document.getElementById("result-count");
const commandList = document.getElementById("command-list");
const backBtn = document.getElementById("back-btn");
const roleLink = document.getElementById("role-link");

let synonyms = {};        // { providerId: { normalizedPhrase: canonicalCommand } }
let activeProviderId = "";
let commands = [];        // currently loaded provider's commands

function norm(s) {
  return s.toLowerCase().trim().replace(/\s+/g, " ");
}

async function loadSynonyms() {
  try {
    const res = await fetch(DATA_DIR + "synonyms.json");
    const raw = await res.json();
    const out = {};
    for (const providerKey of Object.keys(raw)) {
      const providerId = norm(providerKey);
      const bucket = raw[providerKey];
      out[providerId] = {};
      for (const phrase of Object.keys(bucket)) {
        out[providerId][norm(phrase)] = bucket[phrase];
      }
    }
    synonyms = out;
  } catch (e) {
    console.warn("Could not load synonyms.json", e);
    synonyms = {};
  }
}

async function loadProvider(providerId, title, file) {
  const res = await fetch(DATA_DIR + file);
  commands = await res.json();
  activeProviderId = providerId;
  providerTitle.textContent = title;
  providerSelect.hidden = true;
  providerView.hidden = false;
  searchInput.value = "";
  render(commands);
  searchInput.focus();
}

function search(keyword) {
  if (!keyword) return commands;

  const terms = [keyword];
  const bucket = synonyms[activeProviderId];
  if (bucket) {
    const canonical = bucket[norm(keyword)];
    if (canonical) terms.push(canonical);
  }

  const uniqueLower = [...new Set(terms.map(norm))];

  return commands.filter(c => {
    const cmdL = c.command.toLowerCase();
    const descL = c.description.toLowerCase();
    return uniqueLower.some(t => cmdL.includes(t) || descL.includes(t));
  });
}

function render(list) {
  commandList.innerHTML = "";
  resultCount.textContent = `${list.length} command${list.length === 1 ? "" : "s"}`;

  if (list.length === 0) {
    const li = document.createElement("li");
    li.className = "no-results";
    li.textContent = "No matching commands.";
    commandList.appendChild(li);
    return;
  }

  list.forEach((c, i) => {
    const li = document.createElement("li");
    li.className = "cmd-item";

    const row = document.createElement("div");
    row.className = "cmd-row";

    const index = document.createElement("span");
    index.className = "cmd-index";
    index.textContent = `${i + 1}.`;

    const cmdText = document.createElement("code");
    cmdText.className = "cmd-text";
    cmdText.textContent = c.command;

    const arrow = document.createElement("span");
    arrow.className = "cmd-desc";
    arrow.textContent = "→ " + c.description;

    row.append(index, cmdText, arrow);
    li.appendChild(row);

    if (Array.isArray(c.examples) && c.examples.length > 0) {
      row.classList.add("has-examples");

      const caret = document.createElement("span");
      caret.className = "cmd-caret";
      caret.textContent = "▸";
      row.appendChild(caret);

      const examplesEl = document.createElement("div");
      examplesEl.className = "cmd-examples";
      examplesEl.hidden = true;

      const label = document.createElement("div");
      label.className = "examples-label";
      label.textContent = "Examples";
      examplesEl.appendChild(label);

      c.examples.forEach((ex) => {
        const exLine = document.createElement("code");
        exLine.className = "example-line";
        exLine.textContent = ex;
        examplesEl.appendChild(exLine);
      });

      li.appendChild(examplesEl);

      row.addEventListener("click", () => {
        examplesEl.hidden = !examplesEl.hidden;
        row.classList.toggle("expanded", !examplesEl.hidden);
        caret.textContent = examplesEl.hidden ? "▸" : "▾";
      });
    }

    commandList.appendChild(li);
  });
}

providerSelect.addEventListener("click", (e) => {
  const card = e.target.closest(".provider-card");
  if (!card) return;
  loadProvider(card.dataset.provider, card.querySelector(".provider-name").textContent, card.dataset.file);
});

backBtn.addEventListener("click", () => {
  providerView.hidden = true;
  providerSelect.hidden = false;
  activeProviderId = "";
  commands = [];
});

searchInput.addEventListener("input", () => {
  render(search(searchInput.value));
});

async function loadRoleLink() {
  try {
    const res = await fetch("/api/me");
    if (!res.ok) return;
    const data = await res.json();
    if (data.role === "headteacher") {
      roleLink.textContent = "Headteacher Dashboard";
      roleLink.href = "/headteacher.html";
      roleLink.hidden = false;
    } else if (data.role === "teacher") {
      roleLink.textContent = "Teacher Dashboard";
      roleLink.href = "/teacher.html";
      roleLink.hidden = false;
    } else if (data.role === "student") {
      roleLink.textContent = "Take a Quiz";
      roleLink.href = "/quiz.html";
      roleLink.hidden = false;
    }
  } catch (e) {
    console.warn("Could not load role", e);
  }
}

loadSynonyms();
loadRoleLink();
