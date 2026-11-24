// Plain-SVG chart helpers (no libraries). Exposed as Charts.*
(function () {
  const NS = "http://www.w3.org/2000/svg";
  function svg(tag, attrs, ...kids) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  }

  // Colours per protocol (from the mockup). Unknown protocols get the next spare colour.
  const KNOWN = { "plain": "#4a4658", "mini vpn": "#a78bfa", "wireguard": "#8f8aa3", "openvpn": "#bdb8cc", "gre": "#6c6780" };
  const SPARE = ["#7a9cc6", "#c68a7a", "#7ac6a0", "#c6b87a", "#b07ac6"];
  const assigned = {};
  function colorFor(protocol) {
    const key = protocol.toLowerCase();
    if (KNOWN[key]) return KNOWN[key];
    if (!assigned[key]) assigned[key] = SPARE[Object.keys(assigned).length % SPARE.length];
    return assigned[key];
  }

  // Number with about 3 useful digits: 940, 19.1, 0.40
  function fmt(v) {
    const a = Math.abs(v);
    return a >= 100 ? v.toFixed(0) : a >= 10 ? v.toFixed(1) : v.toFixed(2);
  }

  function niceMax(v) {
    if (!(v > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  // Grouped bar chart with mean ± std whiskers.
  //   groups: [{label, bars: [{protocol, mean, std}]}]   log: true = log10 y axis
  // Bars are in the order given. Hover shows the exact numbers (SVG <title>).
  function barChart(groups, { log = false, unit = "" } = {}) {
    const W = 400, H = 210, top = 10, bottom = H - 28, left = 12, right = W - 8;
    const all = groups.flatMap(g => g.bars);
    let lo = 0, hi;
    const tops = all.map(b => b.mean + b.std);
    if (log) {
      const pos = all.map(b => b.mean).filter(v => v > 0);
      const min = pos.length ? Math.min(...pos) : 1;
      lo = Math.pow(10, Math.floor(Math.log10(min)));
      if (min <= lo * 1.0001) lo /= 10;              // keep the smallest bar visible
      hi = Math.pow(10, Math.ceil(Math.log10(Math.max(...tops, lo * 10))));
    } else {
      hi = niceMax(Math.max(...tops, 0));
    }
    const yOf = v => {
      let f;
      if (log) f = v > lo ? Math.log10(v / lo) / Math.log10(hi / lo) : 0;
      else f = Math.max(0, v) / hi;
      return bottom - Math.min(1, f) * (bottom - top);
    };

    const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
    // gridlines: one per decade on the log chart, four evenly spaced lines otherwise
    const lines = [];
    if (log) for (let v = lo; v <= hi * 1.0001; v *= 10) lines.push(v);
    else for (let i = 0; i <= 4; i++) lines.push(hi * i / 4);
    for (const v of lines) s.append(svg("line", { class: "grid", x1: left, x2: right, y1: yOf(v), y2: yOf(v) }));

    const gw = (right - left) / groups.length, pad = gw * 0.12;
    groups.forEach((g, gi) => {
      s.append(svg("text", { class: "grp", x: left + gi * gw + gw / 2, y: H - 8, "text-anchor": "middle" }, g.label));
      const n = g.bars.length, bw = (gw - 2 * pad) / n * 0.82, step = (gw - 2 * pad) / n;
      g.bars.forEach((b, bi) => {
        const x = left + gi * gw + pad + bi * step + (step - bw) / 2, y = yOf(b.mean);
        const grp = svg("g", {}, svg("title", {}, `${b.protocol} · ${g.label}: ${fmt(b.mean)} ± ${fmt(b.std)} ${unit}`));
        grp.append(svg("rect", { x, y, width: bw, height: Math.max(0, bottom - y), rx: 2, fill: colorFor(b.protocol) }));
        if (b.std > 0) {                                    // whisker: mean ± std, clamped to the axis
          const cx = x + bw / 2, y1 = yOf(b.mean + b.std), y2 = yOf(Math.max(b.mean - b.std, log ? lo : 0));
          grp.append(svg("line", { class: "err", x1: cx, x2: cx, y1, y2 }),
                     svg("line", { class: "err", x1: cx - 3, x2: cx + 3, y1, y2: y1 }),
                     svg("line", { class: "err", x1: cx - 3, x2: cx + 3, y1: y2, y2 }));
        }
        s.append(grp);
      });
    });
    return s;
  }

  // Filled line chart of equally spaced numbers (the live throughput graph). Linear axis.
  function areaChart(values) {
    const W = 460, H = 280, left = 4, right = W - 4, top = 14, bottom = H - 30;
    // y axis is never shorter than 1 Mbit/s, so idle traffic shows as a line at the bottom
    const max = niceMax(Math.max(...values, 1));
    const x = i => left + i * (right - left) / Math.max(1, values.length - 1);
    const y = v => bottom - (v / max) * (bottom - top);
    const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
    const defs = svg("defs", {}, svg("linearGradient", { id: "areafill", x1: 0, x2: 0, y1: 0, y2: 1 },
      svg("stop", { offset: "0%", "stop-color": "#a78bfa", "stop-opacity": ".55" }),
      svg("stop", { offset: "100%", "stop-color": "#a78bfa", "stop-opacity": ".03" })));
    s.append(defs);
    for (let i = 0; i <= 3; i++) {
      const gy = top + i * (bottom - top) / 3;
      s.append(svg("line", { x1: left, x2: right, y1: gy, y2: gy, stroke: "#2b2838" }));
    }
    const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
    s.append(svg("polygon", { points: `${left},${bottom} ${pts.join(" ")} ${right},${bottom}`, fill: "url(#areafill)" }),
             svg("polyline", { points: pts.join(" "), fill: "none", stroke: "#a78bfa", "stroke-width": 2, "stroke-linejoin": "round" }),
             svg("text", { class: "ax", x: left, y: H - 8 }, "-60s"),
             svg("text", { class: "ax", x: right, y: H - 8, "text-anchor": "end" }, "now"),
             svg("text", { class: "ax", x: right, y: top - 3, "text-anchor": "end" }, `${max} Mbit/s`));
    return s;
  }

  window.Charts = { svg, colorFor, fmt, barChart, areaChart };
})();
