// The Packet Inspector page: the last 20 packets the Mini VPN server saw (read-only, metadata only).
// It asks /api/packets once a second, but only while this tab is open.
(function () {
  const { el } = Dashboard;
  let ui = {};
  let timer = null;

  const clock = t => {
    const d = new Date(t * 1000);
    return d.toLocaleTimeString("en-GB") + "." + String(d.getMilliseconds()).padStart(3, "0");
  };
  const addr = (ip, port) => `${ip}:${port}`;

  function build(root) {
    ui.msg = el("div", { class: "empty" }, "no packets yet");
    ui.body = el("tbody");
    ui.table = el("table", { class: "pkts" },
      el("thead", {}, el("tr", {},
        ["Time", "Direction", "Outer: from", "Outer: to", "Size", "Type", "Session", "Epoch", "Counter",
         "Inner: from", "Inner: to", "Proto", "Inner size", "Result"].map(h => el("th", {}, h)))),
      ui.body);
    root.append(el("div", { class: "card" },
      el("div", { class: "label" }, "Packet inspector · last 20 packets (newest first)"),
      el("div", { class: "note" }, "Mini VPN server only. Only addresses, sizes and header fields are shown, never payload, keys or passwords. " +
        "For a dropped packet the header numbers are unchecked."),
      ui.msg, el("div", { class: "scroll" }, ui.table)));
    render([]);
  }

  function row(p) {
    const o = p.outer, h = p.header, i = p.inner;
    const dropped = p.result === "dropped";
    const none = el("span", { class: "dim" }, "–");
    return el("tr", { class: dropped ? "bad" : "" },
      el("td", {}, clock(p.time)),
      el("td", {}, p.direction === "client to server" ? "client → server" : "server → client"),
      el("td", {}, addr(o.src_ip, o.src_port)), el("td", {}, addr(o.dst_ip, o.dst_port)), el("td", {}, o.size + " B"),
      el("td", {}, h ? h.type : none), el("td", {}, h ? h.session_id : none),
      el("td", {}, h ? h.key_epoch : none), el("td", {}, h ? h.counter : none),
      el("td", {}, i ? i.src : none), el("td", {}, i ? i.dst : none),
      el("td", {}, i ? i.protocol : none), el("td", {}, i ? i.size + " B" : none),
      el("td", { class: "res" }, dropped ? "dropped: " + p.reason : "accepted"));
  }

  function render(packets) {
    ui.msg.style.display = packets.length ? "none" : "";
    ui.table.style.display = packets.length ? "" : "none";
    ui.body.replaceChildren(...packets.map(row));
  }

  async function refresh() {
    let packets = [];
    try {
      const r = await fetch("/api/packets", { cache: "no-store" });
      if (r.ok) {
        const d = await r.json();
        if (d.running && Array.isArray(d.packets)) packets = d.packets;   // missing or stale file: running is false
      }
    } catch (e) { /* cannot reach the API: show "no packets yet" */ }
    render(packets);
  }

  Dashboard.registerPage({
    id: "packets", title: "Packet Inspector", build,
    onShow() { refresh(); timer = setInterval(refresh, 1000); },
    onHide() { clearInterval(timer); timer = null; },
  });
})();
