// Mirrors the search/synonym logic in src/engine.cpp so the website and
// the C++ app behave the same way against the same data/*.json files.

const DATA_DIR = "data/";

// `reviewed` is when we last checked the topics against the exam board's own
// published specification, and `basedOn` says which version that was. Update
// both whenever a syllabus file is checked or changed.
const SYLLABUS_REVIEWED = "October 2026";
const SYLLABUS_META = {
  aqa_gcse_cs: {
    label: "AQA GCSE Computer Science",
    hint: "8525 specification, updated for 2027 exams",
    basedOn: "AQA 8525, updated for exams from summer 2027"
  },
  ocr_gcse_cs: {
    label: "OCR GCSE Computer Science",
    hint: "J277 specification, version 3.1 (2026)",
    basedOn: "OCR J277, specification version 3.1 (2026)"
  },
  edexcel_gcse_cs: {
    label: "Edexcel/Pearson GCSE Computer Science",
    hint: "1CP2 specification",
    basedOn: "Pearson Edexcel 1CP2, specification Issue 1 (January 2020)"
  },
  // For independent learners who haven't picked a board: the topics from all three.
  general_cs: {
    label: "General Computer Science",
    hint: "A mixture of AQA, OCR and Edexcel",
    basedOn: "a combination of the AQA 8525 (2027 content), OCR J277 (version 3.1) and Pearson Edexcel 1CP2 specifications"
  }
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
  // Written as escape codes (moon, sun) so they show correctly whatever text
  // encoding the file ends up being served with.
  themeToggleBtn.textContent = isLight ? "\u{1F319}" : "\u{2600}\u{FE0F}";
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

let quizLinkEnabled = false;   // true for students and independent learners (see loadRoleLink)
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

// Points the header's quiz button at the quiz for whatever the learner is
// looking at (e.g. Linux -> /quiz.html?provider=linux), or back at the quiz
// picker when they're not inside a language. Does nothing for teachers and
// headteachers, whose header button goes to their dashboard instead.
function setQuizLink(providerId, title) {
  if (!quizLinkEnabled) return;
  if (providerId) {
    roleLink.href = "/quiz.html?provider=" + encodeURIComponent(providerId);
    // Short names read nicely ("Linux Quiz"); long ones (exam boards) would
    // crowd the header on a phone, so they keep the generic wording.
    roleLink.textContent = title && title.length <= 10 ? title + " Quiz" : "Take a Quiz";
  } else {
    roleLink.href = "/quiz.html";
    roleLink.textContent = "Take a Quiz";
  }
}

function showProviderView(providerId, title, commandsArray) {
  commands = commandsArray;
  activeProviderId = providerId;
  setQuizLink(providerId, title);
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

// Shows the person's syllabus on the home page itself. The exam board is a
// title, and its topics sit underneath in collapsible sections (one per
// section of the specification) with a search box, so there's nothing to
// click through to. Returns true if a syllabus was shown, false if the person
// has none (e.g. their school hasn't picked an exam board yet).
async function loadSyllabusSection() {
  const section = document.getElementById("syllabus-section");
  const empty = document.getElementById("syllabus-empty");
  const body = document.getElementById("syllabus-body");

  let key = null;
  try {
    const res = await fetch("/api/syllabus");
    if (res.ok) key = (await res.json()).syllabus;
  } catch (e) {
    console.warn("Could not load syllabus", e);
  }

  section.hidden = false;
  const meta = key && SYLLABUS_META[key];
  let topics = null;
  if (meta) {
    try {
      topics = await (await fetch(DATA_DIR + "syllabus_" + key + ".json")).json();
    } catch (e) {
      console.warn("Could not load syllabus topics", e);
    }
  }
  if (!meta || !Array.isArray(topics) || topics.length === 0) {
    empty.hidden = false;
    body.hidden = true;
    return false;
  }

  empty.hidden = true;
  body.hidden = false;
  document.getElementById("syllabus-board").textContent = meta.label;
  document.getElementById("syllabus-note").textContent =
    `Based on ${meta.basedOn}. Last reviewed ${SYLLABUS_REVIEWED}. ` +
    "Always check your exam board's official specification for the definitive list of what you need to know.";

  const quizLink = document.getElementById("syllabus-quiz-link");
  if (quizLinkEnabled) {
    quizLink.href = "/quiz.html?provider=syllabus_" + encodeURIComponent(key);
    quizLink.hidden = false;
  }

  // Group topics by section, keeping the order they appear in the file.
  const groups = [];
  const bySection = new Map();
  topics.forEach((t) => {
    if (!bySection.has(t.section)) {
      const g = { name: t.section, topics: [], details: null };
      bySection.set(t.section, g);
      groups.push(g);
    }
    bySection.get(t.section).topics.push({ data: t, el: null, text: norm(`${t.title} ${t.explanation}`) });
  });

  const container = document.getElementById("syllabus-sections");
  container.innerHTML = "";
  groups.forEach((g) => {
    const details = document.createElement("details");
    details.className = "syl-section";

    const summary = document.createElement("summary");
    const name = document.createElement("span");
    name.className = "syl-name";
    name.textContent = g.name;
    const count = document.createElement("span");
    count.className = "syl-count";
    count.textContent = `${g.topics.length} topic${g.topics.length === 1 ? "" : "s"}`;
    summary.append(name, count);
    details.appendChild(summary);

    const list = document.createElement("div");
    list.className = "syl-topics";
    g.topics.forEach((item) => {
      const card = document.createElement("div");
      card.className = "syl-topic";
      const title = document.createElement("h4");
      title.textContent = item.data.title;
      const text = document.createElement("p");
      text.textContent = item.data.explanation;
      card.append(title, text);
      if (item.data.code) {
        const pre = document.createElement("pre");
        const code = document.createElement("code");
        code.textContent = item.data.code;
        pre.appendChild(code);
        card.appendChild(pre);
      }
      item.el = card;
      list.appendChild(card);
    });
    details.appendChild(list);
    g.details = details;
    container.appendChild(details);
  });

  // Search: show only matching topics and open the sections they're in.
  const searchBox = document.getElementById("syllabus-search");
  const countEl = document.getElementById("syllabus-count");
  const overall = `${topics.length} topics in ${groups.length} sections`;
  countEl.textContent = overall;
  searchBox.value = "";
  searchBox.oninput = () => {
    const q = norm(searchBox.value);
    let shown = 0;
    groups.forEach((g) => {
      let inGroup = 0;
      g.topics.forEach((item) => {
        const match = !q || item.text.includes(q);
        item.el.hidden = !match;
        if (match) inGroup++;
      });
      g.details.hidden = inGroup === 0;
      g.details.open = q !== "" && inGroup > 0;
      shown += inGroup;
    });
    countEl.textContent = q ? `${shown} matching topic${shown === 1 ? "" : "s"}` : overall;
  };

  // OCR students do their practical work in Python, so its card sits with the
  // syllabus for that board.
  const primaryLangId = SYLLABUS_PRIMARY_LANGUAGE[key];
  if (primaryLangId) {
    const langCard = document.querySelector(`.provider-card[data-provider="${primaryLangId}"]`);
    if (langCard) document.getElementById("syllabus-extra-cards").appendChild(langCard);
  }
  return true;
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
    arrow.textContent = "\u{2192} " + c.description;

    row.append(index, cmdText, arrow);
    li.appendChild(row);

    if (Array.isArray(c.examples) && c.examples.length > 0) {
      row.classList.add("has-examples");

      const caret = document.createElement("span");
      caret.className = "cmd-caret";
      caret.textContent = "\u{25B8}";
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
        caret.textContent = examplesEl.hidden ? "\u{25B8}" : "\u{25BE}";
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
  setQuizLink(null);
});

// The OmniShell title (and the little house on phones) take you home without
// scrolling: close any open language list and glide back to the top. It's a
// real link to "/" too, so it still works if the script hasn't loaded.
function goHome(e) {
  e.preventDefault();
  if (!providerView.hidden) backBtn.click();
  const calm = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.scrollTo({ top: 0, behavior: calm ? "auto" : "smooth" });
}
["home-link", "home-btn"].forEach((id) => {
  const el = document.getElementById(id);
  if (el) el.addEventListener("click", goHome);
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

// Shows the signed-in person's name and initial in the top-right profile chip.
// Accounts that sign in by email have their address as the username, so we
// show just the part before the @ when there's no display name.
function renderProfileChip(data) {
  const chip = document.getElementById("profile-link");
  if (!chip) return;
  const raw = String(data.displayName || data.username || "").trim();
  if (!raw) return;
  const shown = raw.includes("@") ? raw.split("@")[0] : raw;
  document.getElementById("profile-name").textContent = shown;
  document.getElementById("profile-avatar").textContent = shown.charAt(0).toUpperCase();
  chip.title = "View your profile";
  chip.hidden = false;
}

// ---------- badges on the home page ----------
// Which badges someone has earned comes from the server (/api/me). How they
// look comes from badges.js. Learners also see a few greyed-out badges to aim
// for; teachers and headteachers just see what they've earned.
const NEXT_UP_BADGES = ["first_quiz", "streak_3", "full_marks", "quizzes_10", "mastery_python_bronze", "hat_trick"];
const HOME_BADGE_TILES = 6;

function homeBadgeTile(id, earned) {
  const info = OmniBadges.get(id);
  const tile = document.createElement("div");
  tile.className = "home-badge" + (earned ? "" : " locked");
  tile.title = info.description;
  // The picture is drawn by our own badges.js from a known badge id; no text
  // from the server or the user is ever put in as HTML.
  tile.innerHTML = OmniBadges.svg(id, !earned);
  const name = document.createElement("div");
  name.className = "bname";
  name.textContent = info.name;
  tile.appendChild(name);
  if (!earned) {
    const note = document.createElement("div");
    note.className = "bnote";
    note.textContent = info.description;
    tile.appendChild(note);
  }
  return tile;
}

function renderHomeBadges(role, badges) {
  const section = document.getElementById("home-badges");
  if (!section || typeof OmniBadges === "undefined" || !Array.isArray(badges)) return;

  // Ignore any id this page doesn't know how to draw.
  const earned = badges.filter((b) => b && OmniBadges.get(b.id));
  if (!earned.length) return; // badges aren't available: leave the section hidden

  earned.sort((a, b) => String(b.earnedAt).localeCompare(String(a.earnedAt)));
  const row = document.getElementById("home-badges-row");
  row.replaceChildren();
  earned.slice(0, HOME_BADGE_TILES).forEach((b) => row.appendChild(homeBadgeTile(b.id, true)));

  const isLearner = role === "student" || role === "independent";
  if (isLearner) {
    const have = new Set(earned.map((b) => b.id));
    for (const id of NEXT_UP_BADGES) {
      if (row.children.length >= HOME_BADGE_TILES) break;
      if (!have.has(id) && OmniBadges.get(id)) row.appendChild(homeBadgeTile(id, false));
    }
  }

  const note = document.getElementById("home-badges-note");
  note.textContent = "Take quizzes to earn more badges and build a streak.";
  note.hidden = !(isLearner && earned.length <= 1);
  section.hidden = false;
}

let badgeToastTimer = null;
function showBadgeToast(ids) {
  const toast = document.getElementById("badge-toast");
  if (!toast || typeof OmniBadges === "undefined") return;
  const infos = ids.map((id) => OmniBadges.get(id)).filter(Boolean);
  if (!infos.length) return;

  const first = infos[0];
  const art = document.createElement("div");
  art.innerHTML = OmniBadges.svg(first.id, false);
  const title = document.createElement("div");
  title.className = "toast-title";
  title.textContent = infos.length > 1 ? `You earned ${infos.length} new badges!` : "You earned a badge!";
  const sub = document.createElement("div");
  sub.className = "toast-sub";
  sub.textContent = infos.length > 1 ? infos.map((i) => i.name).join(", ") : `${first.name}: ${first.description}`;
  const text = document.createElement("div");
  text.append(title, sub);
  const close = document.createElement("button");
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss");
  close.textContent = "×";
  close.addEventListener("click", () => { toast.hidden = true; });

  toast.replaceChildren(art.firstChild, text, close);
  toast.hidden = false;
  clearTimeout(badgeToastTimer);
  badgeToastTimer = setTimeout(() => { toast.hidden = true; }, 9000);
}

// Returns the signed-in user's role, or null if it couldn't be determined.
async function loadRoleLink() {
  try {
    const res = await fetch("/api/me");
    if (!res.ok) return null;
    const data = await res.json();
    renderProfileChip(data);
    renderTrialBanner(data.plan);
    renderHomeBadges(data.role, data.badges);
    if (Array.isArray(data.newBadges) && data.newBadges.length) showBadgeToast(data.newBadges);
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
      quizLinkEnabled = true;
    }
    return data.role;
  } catch (e) {
    console.warn("Could not load role", e);
    return null;
  }
}

// Everyone sees their syllabus (their school's exam board, or for an independent
// learner the board they chose or the combined general notes) followed by the
// language references. If the role can't be determined we fall back to the
// school layout, which is what everyone saw before.
async function initHomeLayout() {
  const role = await loadRoleLink();
  const extraHeading = document.getElementById("extra-heading");

  const hasSyllabus = await loadSyllabusSection();

  if (role === "independent") {
    // They always have notes to show; if loading them failed, don't show the
    // school-style "your school hasn't chosen" message to someone with no school.
    if (!hasSyllabus) document.getElementById("syllabus-section").hidden = true;
    extraHeading.textContent = "Languages";
  }
  extraHeading.hidden = false;
}

// Sticky header: the bar is fixed to the top of the screen and shrinks
// smoothly over the first SHRINK_DISTANCE pixels of scrolling (title gets
// smaller, subtitle fades out, bar tightens up). The <header> element is only
// a spacer that keeps the full-size height, so nothing below it jumps.
const SHRINK_DISTANCE = 90;
const siteHeader = document.getElementById("site-header");
const headerBar = siteHeader.querySelector(".header-bar");

function setHeaderProgress(p) {
  headerBar.style.setProperty("--p", p.toFixed(3));
  headerBar.classList.toggle("scrolled", p > 0.02);
  headerBar.classList.toggle("compact", p >= 0.98);
}

function measureHeaderSpacer() {
  const current = parseFloat(headerBar.style.getPropertyValue("--p")) || 0;
  setHeaderProgress(0);
  siteHeader.style.height = headerBar.offsetHeight + "px";
  setHeaderProgress(current);
}

let headerFramePending = false;
function updateHeaderOnScroll() {
  if (headerFramePending) return;
  headerFramePending = true;
  requestAnimationFrame(() => {
    headerFramePending = false;
    setHeaderProgress(Math.min(1, Math.max(0, window.scrollY / SHRINK_DISTANCE)));
  });
}

window.addEventListener("scroll", updateHeaderOnScroll, { passive: true });
window.addEventListener("resize", () => {
  measureHeaderSpacer();
  updateHeaderOnScroll();
});
// The size of the full header depends on the web font, so measure again once
// everything has loaded.
measureHeaderSpacer();
window.addEventListener("load", () => {
  measureHeaderSpacer();
  updateHeaderOnScroll();
});

loadSynonyms();
initHomeLayout();
