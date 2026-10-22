// Tests of the dashboard's pure logic (the BEGIN PURE … END PURE block of assets/index.html).
// tests/ui_logic.rs puts that block in front of this file and runs it with node.
"use strict";
const assert = require("node:assert/strict");

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n" + (e && e.stack || e)); }
}

const ROWS = [
  { ip: "1", cc: "DE", procs: ["chrome.exe", "svc.exe"], last: 100, flagged: false },
  { ip: "2", cc: "DE", procs: ["svc.exe"], last: 40, flagged: true },
  { ip: "3", cc: "NL", procs: ["chrome.exe"], last: 99, flagged: false },
  { ip: "4", cc: "us", procs: [], last: 0, flagged: false },
  { ip: "5", cc: null, procs: ["curl.exe"], last: 100, flagged: true },
];
const DEFS = [
  { id: "country", kind: "multi", get: (r) => r.cc },
  { id: "process", kind: "multi", get: (r) => r.procs },
  { id: "active", kind: "pick", options: [{ v: "5", test: (r) => 100 - r.last <= 5 }, { v: "60", test: (r) => 100 - r.last <= 60 }] },
  { id: "flagged", kind: "flag", test: (r) => r.flagged },
];
const ips = (rows) => rows.map((r) => r.ip).join(",");

test("an empty state matches everything", () => {
  assert.equal(ips(facetFilter({}, DEFS, ROWS)), "1,2,3,4,5");
  assert.equal(ips(facetFilter(undefined, DEFS, ROWS)), "1,2,3,4,5");
  assert.equal(ips(facetFilter({ country: [], active: "", flagged: false }, DEFS, ROWS)), "1,2,3,4,5", "empty values are no filter");
});

test("multi: any of the values, case-insensitive, lists match by any element", () => {
  assert.equal(ips(facetFilter({ country: ["de"] }, DEFS, ROWS)), "1,2");
  assert.equal(ips(facetFilter({ country: ["DE", "US"] }, DEFS, ROWS)), "1,2,4");
  assert.equal(ips(facetFilter({ process: ["svc.exe"] }, DEFS, ROWS)), "1,2");
  assert.equal(ips(facetFilter({ process: ["CHROME.EXE", "curl.exe"] }, DEFS, ROWS)), "1,3,5");
  assert.equal(ips(facetFilter({ country: ["XX"] }, DEFS, ROWS)), "", "an unknown value matches nothing");
});

test("filters combine with and; pick and flag", () => {
  assert.equal(ips(facetFilter({ country: ["DE"], process: ["chrome.exe"] }, DEFS, ROWS)), "1");
  assert.equal(ips(facetFilter({ active: "5" }, DEFS, ROWS)), "1,3,5");
  assert.equal(ips(facetFilter({ active: "60" }, DEFS, ROWS)), "1,2,3,5");
  assert.equal(ips(facetFilter({ active: "nonsense" }, DEFS, ROWS)), "1,2,3,4,5", "an unknown choice is ignored, not an error");
  assert.equal(ips(facetFilter({ flagged: true }, DEFS, ROWS)), "2,5");
  assert.equal(ips(facetFilter({ flagged: true, country: ["DE"], active: "5" }, DEFS, ROWS)), "");
});

test("options count with the other filters only, most frequent first, chosen ones stay", () => {
  // With country=DE chosen, every country is still offered (its own filter is ignored)…
  const st = { country: ["DE"] };
  assert.deepEqual(facetOptions(st, DEFS, ROWS, "country"), [{ v: "DE", n: 2 }, { v: "NL", n: 1 }, { v: "us", n: 1 }]);
  // …but the programs are those of German hosts.
  assert.deepEqual(facetOptions(st, DEFS, ROWS, "process"), [{ v: "svc.exe", n: 2 }, { v: "chrome.exe", n: 1 }]);
  // A chosen value with no rows left is still listed (count 0) so it can be removed.
  assert.deepEqual(facetOptions({ country: ["XX"], flagged: true }, DEFS, ROWS, "country"), [{ v: "DE", n: 1 }, { v: "XX", n: 0 }]);
  // Duplicates inside one row count once.
  assert.deepEqual(facetOptions({}, [{ id: "p", kind: "multi", get: () => ["a", "a"] }], [{}, {}], "p"), [{ v: "a", n: 2 }]);
});

test("toggle adds and removes without touching the old state", () => {
  const a = {};
  const b = facetToggle(a, "country", "DE");
  assert.deepEqual(a, {});
  assert.deepEqual(b, { country: ["DE"] });
  const c = facetToggle(b, "country", "NL");
  assert.deepEqual(c, { country: ["DE", "NL"] });
  assert.deepEqual(facetToggle(c, "country", "de"), { country: ["NL"] }, "case-insensitive removal");
  assert.deepEqual(facetToggle({ country: ["DE"], flagged: true }, "country", "DE"), { flagged: true }, "an emptied list disappears");
  assert.equal(facetCount({ country: ["DE"], flagged: true, active: "", process: [] }), 2);
});

test("URL form round-trips and rejects junk", () => {
  const st = { process: ["a b", "c\"d"], country: ["DE"], active: "300", flagged: true, empty: [], off: false };
  const enc = facetEncode(st);
  assert.equal(enc, '{"active":"300","country":["DE"],"flagged":true,"process":["a b","c\\"d"]}', "sorted keys, inactive ones dropped");
  assert.deepEqual(facetDecode(enc), { active: "300", country: ["DE"], flagged: true, process: ["a b", "c\"d"] });
  assert.equal(facetEncode({}), "");
  assert.equal(facetEncode({ country: [] }), "");
  for (const bad of ["", "{", "[1]", "null", "42", '"x"']) assert.deepEqual(facetDecode(bad), {}, bad);
  assert.deepEqual(facetDecode('{"Bad-Key":["x"],"__proto__":["y"],"ok":[1,"2",{},null],"f":false,"long":"' + "x".repeat(100) + '"}'), { ok: ["1", "2"], long: "x".repeat(40) });
  assert.equal(facetDecode('{"many":' + JSON.stringify(Array.from({ length: 80 }, (_, i) => "v" + i)) + "}").many.length, 50);
});

test("filter-language clauses quote strings and escape quotes", () => {
  assert.equal(filterClause("process", "==", "chrome.exe"), 'process == "chrome.exe"');
  assert.equal(filterClause("org", "==", 'A "B" \\ C'), 'org == "A \\"B\\" \\\\ C"');
  assert.equal(filterClause("asn", "==", 15169), "asn == 15169");
  assert.equal(filterClause("port", "==", "443"), "port == 443");
  assert.equal(filterClause("country", "==", "DE"), 'country == "DE"');
});

test("clauses are added once and toggled", () => {
  assert.equal(addClause("", "lan"), "lan");
  assert.equal(addClause("  ", "lan"), "lan");
  assert.equal(addClause("chrome", "lan"), "chrome and lan");
  assert.equal(addClause("chrome and lan", "lan"), "chrome and lan", "not twice");
  assert.equal(addClause("not lan", "lan"), "not lan and lan", "a different clause is not the same clause");
  assert.ok(!hasClause("not lan", "lan"));
  assert.ok(hasClause("x AND lan", "lan"));
  assert.equal(toggleClause("x and lan and y", "lan"), "x and y");
  assert.equal(toggleClause("lan", "lan"), "");
  assert.equal(toggleClause("x", "lan"), "x and lan");
});

test("points of one city become one cluster at the heaviest point", () => {
  const pts = [
    { lat: 52.52, lon: 13.40, weight: 10, id: "berlin-a" },
    { lat: 52.53, lon: 13.41, weight: 30, id: "berlin-b" },
    { lat: 48.85, lon: 2.35, weight: 5, id: "paris" },
    { lat: 52.52, lon: 13.40, weight: 0, id: "berlin-c" },
  ];
  const cs = clusterPoints(pts);
  assert.equal(cs.length, 2);
  assert.deepEqual(cs[0].items.map((i) => i.id), ["berlin-b", "berlin-a", "berlin-c"], "heaviest first");
  assert.equal(cs[0].weight, 40);
  assert.deepEqual([cs[0].lat, cs[0].lon], [52.53, 13.41], "at a real point, not an average");
  assert.equal(cs[1].items[0].id, "paris");
  assert.notEqual(cs[0].key, cs[1].key);
  assert.equal(clusterPoints([{ lat: 0, lon: 0 }, { lat: 0, lon: 179.9 }, { lat: 0, lon: -179.9 }]).length, 3);
  assert.equal(clusterPoints([]).length, 0);
});

const VIEW = { x: 0, y: 0, w: 1000, h: 500 };
const overlap = (a, b, w, h) => a.x < b.x + w && b.x < a.x + w && a.y < b.y + h && b.y < a.y + h;

test("labels never overlap each other and stay in view", () => {
  // Twenty dots in a tight row: their labels cannot all fit.
  const items = Array.from({ length: 20 }, (_, i) => ({ id: "p" + i, x: 400 + i * 6, y: 250, r: 2, w: 60, h: 10, prio: 100 - i }));
  const out = placeLabels(items, VIEW);
  const ids = Object.keys(out);
  assert.ok(ids.length >= 2 && ids.length < 20, `some, not all: ${ids.length}`);
  assert.ok(out.p0, "the most important label is placed");
  for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) assert.ok(!overlap(out[ids[i]], out[ids[j]], 60, 10), `${ids[i]} / ${ids[j]}`);
  for (const id of ids) { const p = out[id]; assert.ok(p.x >= 0 && p.y >= 0 && p.x + 60 <= 1000 && p.y + 10 <= 500); }
  // A label does not cover another dot.
  for (const id of ids) for (const it of items) {
    if (it.id === id) continue;
    const p = out[id], d = { x: it.x - it.r, y: it.y - it.r, w: 2 * it.r, h: 2 * it.r };
    assert.ok(!(p.x < d.x + d.w && d.x < p.x + 60 && p.y < d.y + d.h && d.y < p.y + 10), `${id} covers ${it.id}`);
  }
});

test("labels try the other sides when the right one is taken or off the map", () => {
  const edge = placeLabels([{ id: "e", x: 995, y: 250, r: 3, w: 50, h: 10, prio: 1 }], VIEW);
  assert.ok(edge.e && edge.e.x + 50 <= 995, "placed to the left at the right edge");
  const top = placeLabels([{ id: "t", x: 500, y: 2, r: 2, w: 1200, h: 10, prio: 1 }], VIEW);
  assert.deepEqual(top, {}, "too wide for any side: dropped");
  const outside = placeLabels([{ id: "o", x: 1500, y: 250, r: 2, w: 20, h: 10, prio: 1 }], VIEW);
  assert.deepEqual(outside, {}, "dots outside the viewport get no label");
});

test("important labels win, always-labels are never dropped, max limits the rest", () => {
  const a = { id: "low", x: 500, y: 250, r: 2, w: 80, h: 10, prio: 1 };
  const b = { id: "high", x: 502, y: 250, r: 2, w: 80, h: 10, prio: 9 };
  const out = placeLabels([a, b], VIEW);
  assert.ok(out.high);
  const crowd = Array.from({ length: 8 }, (_, i) => ({ id: "c" + i, x: 500, y: 250, r: 30, w: 200, h: 40, prio: 50 }));
  const always = { id: "exit", x: 500, y: 250, r: 8, w: 120, h: 12, prio: 0, always: true };
  const placed = placeLabels(crowd.concat([always]), VIEW);
  assert.ok(placed.exit, "an always-label is placed even when crowded");
  const many = Array.from({ length: 30 }, (_, i) => ({ id: "m" + i, x: 30 + (i % 10) * 95, y: 40 + Math.floor(i / 10) * 150, r: 2, w: 40, h: 10, prio: i }));
  assert.equal(Object.keys(placeLabels(many, VIEW)).length, 30, "room for all");
  const capped = placeLabels(many, VIEW, 5);
  assert.equal(Object.keys(capped).length, 5);
  assert.deepEqual(Object.keys(capped).sort(), ["m25", "m26", "m27", "m28", "m29"], "the five most important");
  assert.equal(Object.keys(placeLabels(many.concat([{ ...always, x: 900, y: 450 }]), VIEW, 0)).join(), "exit", "max does not count always-labels");
});

if (failed) { console.log(failed + " failed"); process.exit(1); }
console.log("all passed");
