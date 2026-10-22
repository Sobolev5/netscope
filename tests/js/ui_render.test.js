// Smoke test of the whole dashboard script: every view renders a real snapshot (from the
// demo traffic, see tests/ui_logic.rs) in both languages, with and without filters, without
// throwing and without untranslated filter labels. The DOM is a stub: only the HTML a view
// produces is checked, layout is not.
//   node ui_render.test.js <page script> <fixture.json>
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");

const [script, fixturePath] = process.argv.slice(2);
const code = fs.readFileSync(script, "utf8");
const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

function element() {
  const own = { innerHTML: "", textContent: "", value: "", title: "", style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false } };
  return new Proxy(own, {
    get(t, k) {
      if (k in t) return t[k];
      if (k === "querySelectorAll") return () => [];
      if (k === "querySelector" || k === "closest") return () => null;
      if (typeof k === "symbol") return undefined;
      return () => undefined;
    },
    set(t, k, v) { t[k] = v; return true; },
  });
}

/** Loads the page script into a fresh fake browser; returns the hooks the tests drive. */
function boot(lang) {
  const els = {};
  const storage = new Map();
  const env = {
    window: null,
    document: { getElementById: (id) => (els[id] ||= element()), querySelector: () => null, querySelectorAll: () => [], addEventListener() {}, createElement: () => element(), documentElement: element(), body: element(), activeElement: null, hidden: false },
    location: { hash: "#/overview", search: "?lang=" + lang, protocol: "http:", host: "127.0.0.1:1", pathname: "/" },
    history: { replaceState(_s, _t, h) { env.location.hash = h; } },
    localStorage: { getItem: (k) => (storage.has(k) ? storage.get(k) : null), setItem: (k, v) => storage.set(k, String(v)), removeItem: (k) => storage.delete(k) },
    navigator: { language: lang },
    WebSocket: class { close() {} },
    fetch: () => new Promise(() => {}),
    CSS: { escape: (s) => String(s) },
    setInterval: () => 0, clearInterval() {}, setTimeout: () => 0, clearTimeout() {},
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    requestAnimationFrame: () => 0,
    addEventListener() {}, removeEventListener() {},
  };
  env.window = env;
  const names = Object.keys(env);
  const hooks = `;return {
    renderView, ui, setFacets, addFacetValue,
    go(name, params = {}) { route = { name, params }; },
    setLast(s) { last = s; },
    setSockets(x) { sockCache = x; },
    setConnections(x) { connCache = x; },
    html: () => $("view").innerHTML,
  };`;
  // eslint-disable-next-line no-new-func
  const f = new Function(...names, code + hooks);
  return Object.assign(f(...names.map((n) => env[n])), { env });
}

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n" + (e && e.stack || e)); }
}

const VIEWS = ["overview", "processes", "connections", "hosts", "map", "route", "dns", "sockets", "alerts", "journal", "settings"];

function render(app, view, params) {
  app.go(view, params);
  app.renderView(true);
  return app.html();
}

function prepare(app) {
  app.setLast(fx.stats);
  app.ui.dnsData = fx.dns;
  app.setSockets(fx.sockets);
  app.ui.journal.data = fx.journal;
}

for (const lang of ["ru", "en"]) {
  test(`${lang}: every view renders the demo snapshot`, () => {
    const app = boot(lang);
    prepare(app);
    for (const v of VIEWS) {
      const html = render(app, v);
      assert.ok(html.length > 200, `${v} rendered (${html.length} chars)`);
      const raw = html.match(/\bfb_[a-z0-9_]+/);
      assert.equal(raw, null, `${v}: untranslated label ${raw}`);
    }
  });

  test(`${lang}: filter bars and clickable values are there`, () => {
    const app = boot(lang);
    prepare(app);
    const expect = {
      processes: ['data-fv="processes"', 'id="proc-q"', 'data-fflag="temp"'],
      connections: ['data-fq="1"', 'data-fclause="not lan"', 'data-fadd="country"'],
      hosts: ['data-fmulti="country"', 'data-fmulti="process"', 'data-fadd="country"', 'data-fflag="flagged"'],
      map: ['data-fmulti="country"', 'class="map-label"', 'data-mapcluster=', 'data-ftog="country"'],
      dns: ['data-fmulti="rcode"', 'data-fflag="hide_local"', 'data-fadd="qtype"'],
      sockets: ['data-fmulti="proto"', 'data-fflag="exposed"'],
      alerts: ['data-fmulti="category"', 'id="alert-q"', 'data-fpick="period"'],
      journal: ['data-fv="journal:connections"', 'data-fmulti="process"'],
    };
    for (const [v, needles] of Object.entries(expect)) {
      const html = render(app, v);
      for (const n of needles) assert.ok(html.includes(n), `${v}: ${n}`);
    }
  });

  test(`${lang}: filters narrow the lists`, () => {
    const app = boot(lang);
    prepare(app);
    const rows = (html) => (html.match(/<tr class="clickable"/g) || []).length;
    const allHosts = rows(render(app, "hosts"));
    assert.ok(allHosts >= 3, `hosts: ${allHosts}`);
    app.ui.facets.hosts = { country: [fx.country] };
    const some = rows(render(app, "hosts"));
    assert.ok(some > 0 && some < allHosts, `country filter: ${some} of ${allHosts}`);
    assert.ok(app.html().includes('data-fdel="country"'), "the chosen value is a removable chip");
    app.ui.facets.hosts = { country: ["ZZ"] };
    assert.equal(rows(render(app, "hosts")), 0);
    // The map shows only the chosen country's dots and lists just that country.
    app.ui.facets.map = { country: [fx.country] };
    const map = render(app, "map");
    assert.equal((map.match(/data-ftog="country"/g) || []).length, 1, "one country row");
    app.ui.facets.map = {};
    const allMap = render(app, "map");
    assert.ok((allMap.match(/data-ftog="country"/g) || []).length > 1);
    // Processes: a signature status nobody has leaves an empty list, not an error.
    app.ui.facets.processes = { sig: ["invalid"] };
    assert.ok(!render(app, "processes").includes('data-pid="'), "no process rows");
    // Sockets: only the LISTEN on 0.0.0.0 is reachable (not loopback, not a client's UDP port).
    const socks = render(app, "sockets");
    assert.equal((socks.match(/chip bg-amber-100 text-amber-800" title=/g) || []).length, 1, "one reachable socket");
    app.ui.facets.sockets = { exposed: true };
    assert.equal((render(app, "sockets").match(/<tr class="clickable"/g) || []).length, 1);
    app.ui.facets.sockets = {};
    // Alerts by category.
    app.ui.facets.alerts = { category: ["routes"] };
    const html = render(app, "alerts");
    assert.ok(!/data-host=/.test(html) || fx.stats.alerts.some((a) => a.category === "routes"));
  });

  test(`${lang}: a filtered view writes its filters into the address`, () => {
    const app = boot(lang);
    prepare(app);
    app.ui.facets.hosts = { country: [fx.country], flagged: true };
    render(app, "hosts");
    // renderView(true) → schedulePolling → syncFacetUrl
    const hash = app.env.location.hash;
    assert.ok(hash.startsWith("#/hosts?"), hash);
    const f = new URLSearchParams(hash.split("?")[1]).get("f");
    assert.deepEqual(JSON.parse(f), { country: [fx.country], flagged: true });
    app.ui.facets.hosts = {};
    render(app, "hosts");
    assert.equal(app.env.location.hash, "#/hosts", "no filters, no parameter");
    // Picking a value in the bar (or clicking one in the table) updates the address at once.
    app.setFacets("hosts", { proto: ["tls"] });
    assert.deepEqual(JSON.parse(new URLSearchParams(app.env.location.hash.split("?")[1]).get("f")), { proto: ["tls"] });
    app.addFacetValue("country", fx.country);
    assert.deepEqual(JSON.parse(new URLSearchParams(app.env.location.hash.split("?")[1]).get("f")), { country: [fx.country], proto: ["tls"] });
    app.addFacetValue("country", fx.country);
    assert.deepEqual(app.ui.facets.hosts, { proto: ["tls"], country: [fx.country] }, "clicking a chosen value again keeps it");
    // On the connection list a clicked value becomes a query clause.
    render(app, "connections");
    app.addFacetValue("country", "DE");
    assert.equal(app.ui.connQuery, 'country == "DE"');
    // The journal keeps its kind next to the filters.
    app.ui.journal.kind = "dns";
    app.ui.facets["journal:dns"] = { rcode: ["NXDOMAIN"] };
    render(app, "journal");
    const jq = new URLSearchParams(app.env.location.hash.split("?")[1]);
    assert.equal(jq.get("kind"), "dns");
    assert.deepEqual(JSON.parse(jq.get("f")), { rcode: ["NXDOMAIN"] });
  });
}

if (failed) { console.log(failed + " failed"); process.exit(1); }
console.log("all passed");
