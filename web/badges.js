// How badges look and what they're called. WHICH badges someone has earned is
// decided by the server (worker/index.js, badgesFromStats); this file only
// turns a badge id into a name, a description and a picture.
//
// Keep the numbers in MASTERY_COUNTS and the ids in step with the Worker.
// The pictures are drawn from code (no image files), so adding a language or
// changing a colour here is a one-line edit.

const OmniBadges = (function () {
  const LANGUAGES = [
    { id: "linux", name: "Linux", glyph: ">_", fill: "#2f3542" },
    { id: "powershell", name: "PowerShell", glyph: "PS", fill: "#1d3a6b" },
    { id: "python", name: "Python", glyph: "Py", fill: "#2b5fa8" },
    { id: "javascript", name: "JavaScript", glyph: "JS", fill: "#8a6d00" },
    { id: "java", name: "Java", glyph: "Jv", fill: "#a3411c" },
    { id: "cpp", name: "C++", glyph: "C++", fill: "#4a3c9a" },
    { id: "sql", name: "SQL", glyph: "SQL", fill: "#13696b" },
    { id: "git", name: "Git", glyph: "Git", fill: "#9c3b2a" }
  ];

  const TIERS = [
    { key: "bronze", name: "Bronze", label: "Apprentice", ring: "#cd7f32", count: 25 },
    { key: "silver", name: "Silver", label: "Explorer", ring: "#c7ced9", count: 75 },
    { key: "gold", name: "Gold", label: "Master", ring: "#f5c542", count: 150 }
  ];

  const catalogue = {};

  // Language mastery: one hexagon per language, ring colour = level.
  LANGUAGES.forEach((lang) => {
    TIERS.forEach((tier) => {
      catalogue[`mastery_${lang.id}_${tier.key}`] = {
        id: `mastery_${lang.id}_${tier.key}`,
        group: "mastery",
        name: `${lang.name} ${tier.label}`,
        description: `Answer ${tier.count} different ${lang.name} commands correctly (${tier.name})`,
        art: { type: "hex", ring: tier.ring, fill: lang.fill, glyph: lang.glyph, ribbon: tier.name.toUpperCase() }
      };
    });
  });

  [
    ["streak_3", "3-Day Streak", "Take a quiz 3 days in a row", "#f59e0b", "3"],
    ["streak_7", "Week Warrior", "Take a quiz 7 days in a row", "#f97316", "7"],
    ["streak_30", "Unstoppable", "Take a quiz 30 days in a row", "#ef4444", "30"]
  ].forEach(([id, name, description, color, glyph]) => {
    catalogue[id] = { id, group: "streak", name, description, art: { type: "shape", shape: "flame", color, glyph } };
  });

  [
    ["first_quiz", "First Steps", "Finish your first quiz", "circle", "#4fc3f7", "1"],
    ["quizzes_10", "Warming Up", "Finish 10 quizzes", "circle", "#38bdf8", "10"],
    ["quizzes_50", "Quiz Regular", "Finish 50 quizzes", "circle", "#818cf8", "50"],
    ["quizzes_100", "Centurion", "Finish 100 quizzes", "circle", "#c084fc", "100"],
    ["full_marks", "Full Marks", "Get every question right in a quiz of 5 or more", "star", "#f5c542", ""],
    ["hat_trick", "Hat-trick", "Score 90% or more three times", "star", "#f59e0b", "3x"],
    ["comeback", "Comeback", "Beat your last score in a subject by 20 points or more", "shield", "#4cd08a", "+"],
    ["polyglot", "Polyglot", "Take a quiz in all 8 languages", "diamond", "#22d3ee", "8"]
  ].forEach(([id, name, description, shape, color, glyph]) => {
    catalogue[id] = { id, group: "milestone", name, description, art: { type: "shape", shape, color, glyph } };
  });

  function hexSvg(a) {
    const size = a.glyph.length > 2 ? 17 : 24;
    const ribbon = a.ribbon
      ? `<rect x="30" y="78" width="40" height="12" rx="3" fill="${a.ring}" stroke="rgba(0,0,0,.35)"/><text x="50" y="87.5" text-anchor="middle" font-size="8" font-weight="700" fill="#111" font-family="system-ui">${a.ribbon}</text>`
      : "";
    return `<polygon points="50,6 88,28 88,72 50,94 12,72 12,28" fill="${a.ring}"/>
      <polygon points="50,15 80,32 80,68 50,85 20,68 20,32" fill="${a.fill}" stroke="rgba(0,0,0,.35)" stroke-width="1"/>
      <text x="50" y="${a.glyph.length > 2 ? 56 : 58}" text-anchor="middle" font-family="ui-monospace,Consolas,monospace" font-weight="700" font-size="${size}" fill="#fff">${a.glyph}</text>${ribbon}`;
  }

  function shapeSvg(a) {
    const c = a.color;
    const stroke = 'stroke="rgba(0,0,0,.35)" stroke-width="2"';
    const shapes = {
      flame: `<path d="M50 8 C58 28 78 36 74 62 C72 78 62 90 50 90 C36 90 26 78 28 62 C30 50 38 46 40 34 C46 40 48 44 50 8Z" fill="${c}" ${stroke}/><path d="M50 40 C56 54 66 58 62 72 C60 80 56 84 50 84 C43 84 38 79 40 70 C42 62 48 58 50 40Z" fill="#fff" opacity=".35"/>`,
      star: `<polygon points="50,8 62,36 92,38 69,57 77,87 50,70 23,87 31,57 8,38 38,36" fill="${c}" ${stroke}/>`,
      shield: `<path d="M50 6 L88 20 V50 C88 72 70 86 50 94 C30 86 12 72 12 50 V20Z" fill="${c}" ${stroke}/>`,
      circle: `<circle cx="50" cy="50" r="40" fill="${c}" ${stroke}/>`,
      diamond: `<polygon points="50,6 90,50 50,94 10,50" fill="${c}" ${stroke}/>`
    };
    const text = a.glyph
      ? `<text x="50" y="${a.glyph.length > 2 ? 59 : 62}" text-anchor="middle" font-family="system-ui" font-weight="800" font-size="${a.glyph.length > 2 ? 22 : 30}" fill="#111">${a.glyph}</text>`
      : "";
    return shapes[a.shape] + text;
  }

  // Returns an <svg> string for a badge id. `locked` greys it out.
  function svg(id, locked) {
    const b = catalogue[id];
    if (!b) return "";
    const inner = b.art.type === "hex" ? hexSvg(b.art) : shapeSvg(b.art);
    const style = locked ? ' style="opacity:.3;filter:grayscale(.7)"' : "";
    return `<svg viewBox="0 0 100 100" role="img" aria-label="${b.name}"${style}>${inner}</svg>`;
  }

  return { LANGUAGES, TIERS, catalogue, svg, get: (id) => catalogue[id] || null };
})();
