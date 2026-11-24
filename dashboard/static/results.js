// The Results page: bar charts (mean ± standard deviation) and the table, from /api/results.
(function () {
  const { el } = Dashboard;
  let root, timer = null, lastJson = null;

  // What each condition means (the netem presets in lab/netem.sh).
  const CONDITIONS = {
    none: "no impairment (netem off)",
    good: "10 ms delay, 2 ms jitter, 0.1% loss, 100 Mbit",
    normal: "50 ms delay, 10 ms jitter, 1% loss, 20 Mbit",
    bad: "150 ms delay, 30 ms jitter, 5% loss, 5 Mbit",
  };
  const METRICS = [["throughput_mbps", "Mbit/s"], ["rtt_ms", "RTT ms"], ["loss_pct", "Loss %"]];
  const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
  const plusminus = m => `${Charts.fmt(m.mean)} ± ${Charts.fmt(m.std)}`;

  function message(text, small) {
    root.replaceChildren(el("div", { class: "card message" }, text, small ? el("small", {}, small) : null));
  }

  function render(r) {
    if (!r.available) return message("No results yet", r.error || "Run the benchmarks to create results/summary.csv");
    const find = (p, c) => r.stats.find(s => s.protocol === p && s.condition === c);

    const legend = el("div", { class: "card legend" },
      r.protocols.map(p => el("span", { class: "it" }, el("span", { class: "sw", style: "background:" + Charts.colorFor(p) }), p)),
      el("span", { class: "note" }, `Mean ± standard deviation, ${r.max_runs} ${r.max_runs === 1 ? "run" : "runs"}`));

    const charts = el("div", { class: "charts" }, [
      ["throughput_mbps", "Throughput", "Mbit/s · log scale", true],
      ["rtt_ms", "Round-trip delay", "ms", false],
      ["loss_pct", "Packet loss", "%", false],
    ].map(([m, title, unit, log]) => {
      const groups = r.conditions.map(c => ({
        label: cap(c),
        bars: r.protocols.map(p => find(p, c)).filter(Boolean).map(s => ({ protocol: s.protocol, mean: s[m].mean, std: s[m].std })),
      }));
      return el("div", { class: "card" },
        el("div", { class: "head" }, el("h3", {}, title), el("span", { class: "unit" }, unit)),
        Charts.barChart(groups, { log, unit: unit.split(" ")[0] }));
    }));

    const head1 = el("tr", {}, el("th", { class: "first" }), r.conditions.map(c => el("th", { class: "cond", colspan: 3 }, cap(c))));
    const head2 = el("tr", {}, el("th", { class: "first" }, "Protocol"),
      r.conditions.flatMap(() => METRICS.map(([, label], i) => el("th", { class: i === 0 ? "gap" : "" }, label))));
    const rows = r.protocols.map(p => el("tr", { class: /mini\s*vpn/i.test(p) ? "mini" : "" },
      el("td", { class: "first" }, p),
      r.conditions.flatMap(c => METRICS.map(([m], i) => {
        const s = find(p, c);
        return el("td", { class: i === 0 ? "gap" : "" }, s ? plusminus(s[m]) : "–");
      }))));
    const table = el("div", { class: "card tablecard" }, el("table", { class: "res" }, el("thead", {}, head1, head2), el("tbody", {}, rows)));

    const conds = el("div", { class: "card conds" }, r.conditions.map(c =>
      el("div", {}, el("b", {}, cap(c)), el("span", {}, CONDITIONS[c.toLowerCase()] || ""))));

    root.replaceChildren(legend, charts, table, conds);
  }

  async function load() {
    let text;
    try {
      const resp = await fetch("/api/results", { cache: "no-store" });
      if (!resp.ok) throw new Error(resp.status);
      text = await resp.text();
    } catch (e) {
      return message("Cannot load results", "The dashboard cannot reach its API.");
    }
    if (text === lastJson) return;            // nothing changed: leave the page alone
    lastJson = text;
    render(JSON.parse(text));
  }

  Dashboard.registerPage({
    id: "results", title: "Results",
    build(r) { root = r; },
    onShow() { lastJson = null; load(); timer = setInterval(load, 5000); },   // pick up a new CSV while the tab is open
    onHide() { clearInterval(timer); },
  });
})();
