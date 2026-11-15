// The thinking behind the flashcards, with no page code in it so it can be
// tested on its own. It follows Anki's classic spaced-repetition scheduler:
//
//   - New cards go through short "learning steps" (1 minute, then 10 minutes).
//   - Pass the last step and the card "graduates": it's next shown after 1 day.
//   - Review cards come back after longer and longer gaps. Each time you answer:
//       Again = you forgot it  -> it goes back to relearning, and is made "harder"
//       Hard                   -> small increase in the gap, card made a bit harder
//       Good                   -> the gap grows by the card's ease (about x2.5)
//       Easy                   -> a bigger jump, and the card is made easier
//
// Every function takes "now" as a number (milliseconds) instead of reading the
// clock, so the same input always gives the same answer.

const FlashcardsCore = (function () {
  const MIN = 60 * 1000;

  const CONFIG = {
    steps: [1, 10],          // minutes, for new cards
    relearnSteps: [10],      // minutes, after you forget a review card
    graduateDays: 1,         // gap after finishing the learning steps
    easyDays: 4,             // gap when you press Easy on a new card
    startEase: 2.5,
    minEase: 1.3,
    hardFactor: 1.2,
    easyBonus: 1.3,
    learnAheadMinutes: 20,   // learning cards due this soon are shown early if nothing else is left
    newPerDay: 20
  };

  // ----- dates -----
  // Review cards are due on a calendar day, not at a time of day.
  function startOfDay(ts, plusDays) {
    const d = new Date(ts);
    return new Date(d.getFullYear(), d.getMonth(), d.getDate() + (plusDays || 0)).getTime();
  }
  function endOfDay(ts) {
    return startOfDay(ts, 1) - 1;
  }
  function dayKey(ts) {
    const d = new Date(ts);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }

  function makeId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  // ----- cards -----
  function newCard(fields, now) {
    return {
      id: fields.id || makeId(),
      deckId: fields.deckId,
      front: fields.front,
      back: fields.back,
      more: fields.more || null,    // longer notes, shown when the learner asks for more detail
      mono: !!fields.mono,          // show the front in a code font (used for commands)
      state: "new",                 // new | learning | relearning | review
      step: 0,
      due: now,
      interval: 0,                  // days (review cards)
      ease: CONFIG.startEase,
      reps: 0,
      lapses: 0,
      created: now,
      last: null
    };
  }

  function stepDue(minutes, now) {
    return now + Math.round(minutes * MIN);
  }

  function graduate(card, now, easy) {
    let days;
    if (card.state === "relearning") {
      days = easy ? Math.max(2, card.interval + 1) : Math.max(1, card.interval);
    } else {
      days = easy ? CONFIG.easyDays : CONFIG.graduateDays;
    }
    return { ...card, state: "review", step: 0, interval: days, due: startOfDay(now, days) };
  }

  function answerLearning(card, rating, now, steps, state) {
    const i = Math.min(card.step, steps.length - 1);
    if (rating === 1) {
      return { ...card, state, step: 0, due: stepDue(steps[0], now) };
    }
    if (rating === 2) {
      const delay = i === 0 && steps.length > 1 ? (steps[0] + steps[1]) / 2 : steps[i];
      return { ...card, state, step: i, due: stepDue(delay, now) };
    }
    if (rating === 3) {
      if (i + 1 < steps.length) {
        return { ...card, state, step: i + 1, due: stepDue(steps[i + 1], now) };
      }
      return graduate({ ...card, state }, now, false);
    }
    return graduate({ ...card, state }, now, true);
  }

  function answerReview(card, rating, now) {
    const ivl = card.interval || 1;
    const hard = Math.max(ivl + 1, Math.round(ivl * CONFIG.hardFactor));
    const good = Math.max(hard + 1, Math.round(ivl * card.ease));
    const easy = Math.max(good + 1, Math.round(ivl * card.ease * CONFIG.easyBonus));

    if (rating === 1) {
      return {
        ...card,
        state: "relearning",
        step: 0,
        interval: 1,
        lapses: card.lapses + 1,
        ease: Math.max(CONFIG.minEase, card.ease - 0.2),
        due: stepDue(CONFIG.relearnSteps[0], now)
      };
    }
    let interval = good;
    let ease = card.ease;
    if (rating === 2) { interval = hard; ease = Math.max(CONFIG.minEase, ease - 0.15); }
    if (rating === 4) { interval = easy; ease = ease + 0.15; }
    return { ...card, interval, ease, due: startOfDay(now, interval) };
  }

  // rating: 1 Again, 2 Hard, 3 Good, 4 Easy. Returns the updated card (the
  // original is left untouched).
  function answer(card, rating, now) {
    const base = { ...card, reps: card.reps + 1, last: now };
    if (card.state === "review") return answerReview(base, rating, now);
    if (card.state === "relearning") return answerLearning(base, rating, now, CONFIG.relearnSteps, "relearning");
    return answerLearning(base, rating, now, CONFIG.steps, "learning");
  }

  // ----- how long until it's shown again, as text for the buttons -----
  function formatDays(d) {
    if (d < 30) return `${d}d`;
    if (d < 365) return `${(d / 30).toFixed(1).replace(/\.0$/, "")}mo`;
    return `${(d / 365).toFixed(1).replace(/\.0$/, "")}y`;
  }
  function formatMinutes(m) {
    if (m < 1) return "<1m";
    if (m < 60) return `${Math.round(m)}m`;
    if (m < 1440) return `${Math.round(m / 60)}h`;
    return formatDays(Math.round(m / 1440));
  }
  function previews(card, now) {
    const out = {};
    for (let r = 1; r <= 4; r++) {
      const next = answer(card, r, now);
      out[r] = next.state === "review" ? formatDays(next.interval) : formatMinutes((next.due - now) / MIN);
    }
    return out;
  }

  // ----- what to study -----
  // newRemaining: how many new cards may still be started today.
  function buildQueue(cards, now, newRemaining) {
    const eod = endOfDay(now);
    const byDue = (a, b) => a.due - b.due;
    const learning = cards.filter((c) => (c.state === "learning" || c.state === "relearning") && c.due <= eod).sort(byDue);
    const review = cards.filter((c) => c.state === "review" && c.due <= eod).sort(byDue);
    const newCards = cards.filter((c) => c.state === "new").sort((a, b) => a.created - b.created).slice(0, Math.max(0, newRemaining));
    return {
      learning,
      review,
      newCards,
      counts: { new: newCards.length, learn: learning.length, due: review.length }
    };
  }

  // Picks the card to show next. Returns { card, kind } where kind is
  // "learn" | "due" | "new", or { wait } (milliseconds) if only learning cards
  // are left and none is due yet, or null if everything is done.
  function nextCard(queue, now) {
    const dueNow = queue.learning.find((c) => c.due <= now);
    if (dueNow) return { card: dueNow, kind: "learn" };
    if (queue.review.length) return { card: queue.review[0], kind: "due" };
    if (queue.newCards.length) return { card: queue.newCards[0], kind: "new" };
    const ahead = queue.learning.find((c) => c.due <= now + CONFIG.learnAheadMinutes * MIN);
    if (ahead) return { card: ahead, kind: "learn" };
    if (queue.learning.length) return { wait: queue.learning[0].due - now };
    return null;
  }

  // ----- import / export (plain text, one card per line: front TAB back) -----
  function parseImport(text) {
    const cards = [];
    let skipped = 0;
    String(text || "").split(/\r?\n/).forEach((line) => {
      if (!line.trim()) return;
      let idx = line.indexOf("\t");
      if (idx < 0) idx = line.indexOf(";");
      if (idx < 0) { skipped++; return; }
      const front = line.slice(0, idx).trim();
      const back = line.slice(idx + 1).trim();
      if (!front || !back) { skipped++; return; }
      cards.push({ front, back });
    });
    return { cards, skipped };
  }

  function toExportText(cards) {
    // tabs and line breaks inside a card are turned into spaces so each card stays on one line
    const flat = (s) => String(s).replace(/[\t\r\n]+/g, " ").trim();
    return cards.map((c) => `${flat(c.front)}\t${flat(c.back)}`).join("\n") + "\n";
  }

  // ----- quick test (multiple choice built from a deck) -----
  function shuffled(list, rng) {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor((rng || Math.random)() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }
  // Returns null if the deck doesn't have 4 different answers to choose between.
  function buildTest(cards, count, rng) {
    const distinctBacks = [...new Set(cards.map((c) => c.back))];
    if (cards.length < 4 || distinctBacks.length < 4) return null;
    return shuffled(cards, rng).slice(0, count).map((card) => {
      const wrong = shuffled(distinctBacks.filter((b) => b !== card.back), rng).slice(0, 3);
      const options = shuffled([card.back, ...wrong], rng);
      return { card, options, correctIndex: options.indexOf(card.back) };
    });
  }

  return {
    CONFIG, MIN, startOfDay, endOfDay, dayKey, makeId, newCard, answer, previews,
    buildQueue, nextCard, parseImport, toExportText, buildTest, formatDays, formatMinutes
  };
})();
