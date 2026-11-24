// The Live page: clients, counters, topology, throughput graph and security events.
(function () {
  const { el } = Dashboard;
  const open = new Set();          // names of clients whose card is expanded
  let seenClients = new Set();
  let ui = {};

  const EVENT_COLORS = { "rekeyed": "#b49cff", "wrong source dropped": "#f0a070", "login refused": "#f08a8a",
                         "replay dropped": "#f0c36f", "login ok": "#6fd6a0" };
  const TILES = [["handshakes", "Handshakes", "#ece9f4"], ["refused_logins", "Refused logins", "#f08a8a"],
                 ["rekeys", "Rekeys", "#b49cff"], ["replay_drops", "Replay drops", "#f0c36f"],
                 ["wrong_source_drops", "Wrong-source drops", "#f0a070"]];

  function bytes(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
    return n + " B";
  }
  function duration(s) {
    const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
    return h ? `${h}h ${String(m).padStart(2, "0")}m` : m ? `${m}m ${String(sec).padStart(2, "0")}s` : `${sec}s`;
  }
  const clock = t => new Date(t * 1000).toLocaleTimeString("en-GB");   // 14:21:03

  function build(root) {
    ui.clients = el("div", { class: "card clients" });
    ui.tiles = TILES.map(([key, name, color]) => {
      const num = el("div", { class: "num", style: "color:" + color }, "0");
      return { key, num, node: el("div", { class: "card tile" }, el("div", { class: "name" }, name), num) };
    });
    ui.svg = Topology.build();
    ui.chart = el("div", { class: "chart" });
    ui.big = el("span", {}, "0.0");
    ui.events = el("ul");
    root.append(el("div", { class: "live" },
      el("div", { class: "col" },
        ui.clients,
        el("div", { class: "card enc" }, el("div", { class: "label" }, "Encryption"),
          el("div", { class: "algs" }, "AES-256-GCM · X25519 · Ed25519"))),
      el("div", { class: "col" },
        el("div", { class: "tiles" }, ui.tiles.map(t => t.node)),
        el("div", { class: "card topo" }, el("div", { class: "label" }, "Network topology"), ui.svg),
        el("div", { class: "bottom" },
          el("div", { class: "card thr" },
            el("div", { class: "head" }, el("span", { class: "label" }, "Throughput · last 60 s"),
              el("span", { class: "big" }, ui.big, el("small", {}, "Mbit/s"))),
            ui.chart),
          el("div", { class: "card evt" }, el("div", { class: "head" }, el("span", { class: "label" }, "Security events")),
            ui.events)))));
    render({ running: false });
  }

  function renderClients(clients) {
    ui.clients.replaceChildren(el("div", { class: "label" }, "Connected clients"));
    if (!clients.length) ui.clients.append(el("div", { class: "empty" }, "No clients connected"));
    clients.forEach((c, i) => {
      if (!seenClients.has(c.name) && i === 0 && open.size === 0) open.add(c.name);   // first client starts open
      const isOpen = open.has(c.name);
      const kv = (k, v, cls) => el("div", { class: "kv" }, el("span", {}, k), el("b", { class: cls || "" }, v));
      const card = el("div", { class: "client" + (isOpen ? " open" : "") },
        el("div", { class: "row" }, el("span", { class: "dot" }), el("span", { class: "nm", title: c.name }, c.name),
          el("span", { class: "ip" }, c.tunnel_ip), el("span", { class: "caret" }, isOpen ? "▲" : "▼")),
        el("div", { class: "detail" },
          kv("Bytes in", bytes(c.bytes_in)), kv("Bytes out", bytes(c.bytes_out)),
          kv("Key epoch", String(c.key_epoch), "epoch"), kv("Real address", c.real_address || "unknown yet"),
          kv("Connected", duration(c.connected_seconds))));
      card.addEventListener("click", () => { open.has(c.name) ? open.delete(c.name) : open.add(c.name); renderClients(lastClients); });
      ui.clients.append(card);
    });
    seenClients = new Set(clients.map(c => c.name));
  }

  function renderEvents(events) {
    const keep = ui.events.scrollTop;
    ui.events.replaceChildren();
    if (!events.length) ui.events.append(el("li", {}, el("span", { class: "t" }, ""), el("span", {}), el("span", { class: "ty", style: "color:var(--muted)" }, "No events yet"), el("span")));
    for (const e of events) {
      const color = EVENT_COLORS[e.type] || "#9d97b0";
      const who = [e.client, e.detail].filter(Boolean).join(" · ");
      ui.events.append(el("li", {},
        el("span", { class: "t" }, clock(e.time)), el("span", { class: "dot", style: "background:" + color }),
        el("span", { class: "ty", style: "color:" + color }, e.type), el("span", { class: "who", title: who }, who)));
    }
    ui.events.scrollTop = keep;
  }

  let lastClients = [];
  function render(s) {
    lastClients = s.running ? s.clients : [];
    renderClients(lastClients);
    for (const t of ui.tiles) t.num.textContent = s.running ? s.counters[t.key] : "–";
    Topology.update(ui.svg, lastClients);
    const tp = s.running ? s.throughput_mbps : new Array(60).fill(0);
    ui.big.textContent = (tp[tp.length - 1] || 0).toFixed(1);
    ui.chart.replaceChildren(Charts.areaChart(tp));
    renderEvents(s.running ? s.events : []);
  }

  Dashboard.registerPage({ id: "live", title: "Live", build, onStats: render });
})();
