// Mirrors the search/synonym logic in src/engine.cpp so the website and
// the C++ app behave the same way against the same data/*.json files.

const DATA_DIR = "data/";

const SYLLABUS_META = {
  aqa_gcse_cs: { label: "AQA GCSE Computer Science", hint: "8525 specification" },
  ocr_gcse_cs: { label: "OCR GCSE Computer Science", hint: "J277 specification" },
  edexcel_gcse_cs: { label: "Edexcel/Pearson GCSE Computer Science", hint: "1CP2 specification" }
};

// OCR's practical component is taught in Python at almost every UK school,
// so for OCR (only, for now) the Python card moves out of "Extra learning
// material" and sits alongside the topic browser under "Syllabus".
const SYLLABUS_PRIMARY_LANGUAGE = {
  ocr_gcse_cs: "python"
};

const themeToggleBtn = document.getElementById("theme-toggle");

function updateThemeToggleLabel() {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  themeToggleBtn.textContent = isLight ? "🌙" : "☀️";
  themeToggleBtn.setAttribute("aria-label", isLight ? "Switch to dark theme" : "Switch to light theme");
}

themeToggleBtn.addEventListener("click", () => {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  if (isLight) {
    document.documentElement.removeAttribute("data-theme");
    localStorage.setItem("omnishell_theme", "dark");
  } else {
    document.documentElement.setAttribute("data-theme", "light");
    localStorage.setItem("omnishell_theme", "light");
  }
  updateThemeToggleLabel();
});

updateThemeToggleLabel();

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

function showProviderView(providerId, title, commandsArray) {
  commands = commandsArray;
  activeProviderId = providerId;
  providerTitle.textContent = title;
  providerSelect.hidden = true;
  providerView.hidden = false;
  searchInput.value = "";
  render(commands);
  searchInput.focus();
}

async function loadProvider(providerId, title, file) {
  const res = await fetch(DATA_DIR + file);
  const data = await res.json();
  showProviderView(providerId, title, data);
}

async function loadSyllabusProvider(key, title) {
  const res = await fetch(DATA_DIR + "syllabus_" + key + ".json");
  const topics = await res.json();
  const mapped = topics.map((t) => ({
    command: t.title,
    description: t.section + " — " + t.explanation,
    examples: t.code ? [t.code] : []
  }));
  showProviderView("syllabus_" + key, title, mapped);
}

async function loadSyllabusCard() {
  try {
    const res = await fetch("/api/syllabus");
    if (!res.ok) return;
    const data = await res.json();
    const meta = data.syllabus && SYLLABUS_META[data.syllabus];
    if (!meta) return;

    const card = document.createElement("button");
    card.className = "provider-card";
    card.dataset.syllabus = data.syllabus;
    card.innerHTML = `
      <span class="provider-name"></span>
      <span class="provider-hint"></span>
    `;
    card.querySelector(".provider-name").textContent = meta.label;
    card.querySelector(".provider-hint").textContent = meta.hint;

    const extraHeading = document.getElementById("extra-heading");
    extraHeading.before(card);
    document.getElementById("syllabus-empty").hidden = true;

    const primaryLangId = SYLLABUS_PRIMARY_LANGUAGE[data.syllabus];
    if (primaryLangId) {
      const langCard = document.querySelector(`.provider-card[data-provider="${primaryLangId}"]`);
      if (langCard) extraHeading.before(langCard);
    }
  } catch (e) {
    console.warn("Could not load syllabus", e);
  }
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
  if (card.dataset.syllabus) {
    loadSyllabusProvider(card.dataset.syllabus, card.querySelector(".provider-name").textContent);
    return;
  }
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

// Shows the free-trial banner when /api/me reports a trialing plan. The
// Worker doesn't send plan info yet, so until it does this stays hidden.
function renderTrialBanner(plan) {
  const banner = document.getElementById("trial-banner");
  if (!plan || plan.status !== "trialing" || !plan.trialEndsAt) {
    banner.hidden = true;
    return;
  }
  const days = Math.max(0, Math.ceil((new Date(plan.trialEndsAt).getTime() - Date.now()) / 86400000));
  document.getElementById("trial-text").textContent =
    days === 0 ? "Your free trial ends today"
    : days === 1 ? "1 day left in your free trial"
    : `${days} days left in your free trial`;
  banner.hidden = false;
}

// Returns the signed-in user's role, or null if it couldn't be determined.
async function loadRoleLink() {
  try {
    const res = await fetch("/api/me");
    if (!res.ok) return null;
    const data = await res.json();
    renderTrialBanner(data.plan);
    if (data.role === "headteacher") {
      roleLink.textContent = "Headteacher Dashboard";
      roleLink.href = "/headteacher.html";
      roleLink.hidden = false;
    } else if (data.role === "teacher") {
      roleLink.textContent = "Teacher Dashboard";
      roleLink.href = "/teacher.html";
      roleLink.hidden = false;
    } else if (data.role === "student" || data.role === "independent") {
      roleLink.textContent = "Take a Quiz";
      roleLink.href = "/quiz.html";
      roleLink.hidden = false;
    }
    return data.role;
  } catch (e) {
    console.warn("Could not load role", e);
    return null;
  }
}

// School members (headteacher, teacher, student) see their school's syllabus
// and the extra-material heading. Independent learners belong to no school,
// so they just get a plain "Languages" list. If the role can't be determined
// we fall back to the school layout, which is what everyone saw before.
async function initHomeLayout() {
  const role = await loadRoleLink();
  const extraHeading = document.getElementById("extra-heading");

  if (role === "independent") {
    extraHeading.textContent = "Languages";
    extraHeading.hidden = false;
    return;
  }

  document.getElementById("syllabus-heading").hidden = false;
  document.getElementById("syllabus-empty").hidden = false;
  extraHeading.hidden = false;
  await loadSyllabusCard();
}

loadSynonyms();
initHomeLayout();
