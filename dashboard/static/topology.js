// The network diagram. The drawing is fixed (it is the lab from CLAUDE.md); only the client boxes and
// their tunnel lines light up, depending on which clients are connected.
// A connected client is matched by its real address: 10.0.1.2 = client1, .3 = client2, .4 = client3.
(function () {
  const S = Charts.svg;
  const CLIENT_BY_ADDRESS = { "10.0.1.2": "client1", "10.0.1.3": "client2", "10.0.1.4": "client3" };
  const CLIENTS = [  // box position and the tunnel line from its right edge to serverA
    { id: "client1", y: 93,  path: "M143,115 C300,40 600,40 784,128" },
    { id: "client2", y: 182, path: "M143,204 C330,185 600,165 784,148" },
    { id: "client3", y: 272, path: "M143,294 C300,340 650,370 784,176" },
  ];

  function box(cls, x, y, w, h, name, sub, sub2) {
    const g = S("g", { class: cls }, S("rect", { class: "node", x, y, width: w, height: h, rx: 10 }));
    const cx = x + w / 2;
    if (!sub) { g.append(S("text", { class: "nname", x: cx, y: y + h / 2 + 6 }, name)); return g; }
    g.append(S("text", { class: "nname", x: cx, y: y + 28 }, name), S("text", { class: "nsub", x: cx, y: y + 48 }, sub));
    if (sub2) g.append(S("text", { class: "nsub", x: cx, y: y + 68 }, sub2));
    return g;
  }

  function build() {
    const s = S("svg", { viewBox: "0 0 940 405", role: "img", "aria-label": "Network topology" });
    s.append(
      S("rect", { class: "zone", x: 10, y: 25, width: 190, height: 359, rx: 12 }),
      S("text", { class: "zlabel", x: 26, y: 54 }, "10.0.1.0/24"),
      S("rect", { class: "zone", x: 745, y: 25, width: 195, height: 359, rx: 12 }),
      S("text", { class: "zlabel", x: 761, y: 54 }, "10.0.3.0/24"),
      // plain wires (always drawn): client2 - router1 - router2 - servers
      S("line", { class: "wire", x1: 143, y1: 204, x2: 315, y2: 204 }),
      S("line", { class: "wire", x1: 419, y1: 204, x2: 531, y2: 204 }),
      S("line", { class: "wire", x1: 635, y1: 204, x2: 784, y2: 148 }),
      S("line", { class: "wire", x1: 635, y1: 204, x2: 784, y2: 292 }),
      box("", 315, 174, 104, 62, "router1"),
      box("", 531, 174, 104, 62, "router2"),
      S("text", { class: "zlabel", x: 426, y: 228 }, "10.0.2.0/24"),
    );
    for (const c of CLIENTS) s.append(S("path", { class: "tunnel", id: "tun-" + c.id, d: c.path }));
    for (const c of CLIENTS) s.append(box("client-node", 47, c.y, 96, 44, c.id));
    s.append(
      box("hl", 784, 94, 140, 88, "serverA", "10.0.3.2", "tun 10.8.0.1"),
      box("", 784, 271, 140, 68, "serverB", "10.0.3.3"),
      S("text", { class: "tlabel", x: 470, y: 17 }, "encrypted tunnel"),
      S("rect", { class: "badge", x: 257, y: 356, width: 435, height: 40, rx: 20 }),
      S("text", { class: "nname", x: 474, y: 382, style: "font-size:18px" }, "routers see only encrypted bytes"),
    );
    // mark the client groups so update() can find them
    const nodes = s.querySelectorAll(".client-node");
    CLIENTS.forEach((c, i) => nodes[i].id = "node-" + c.id);
    return s;
  }

  // clients = the list from stats.json. Anything not connected goes dim and loses its tunnel line.
  function update(svgEl, clients) {
    const on = new Set(clients.map(c => CLIENT_BY_ADDRESS[c.real_address]).filter(Boolean));
    for (const c of CLIENTS) {
      svgEl.querySelector("#node-" + c.id).classList.toggle("on", on.has(c.id));
      svgEl.querySelector("#tun-" + c.id).classList.toggle("on", on.has(c.id));
    }
  }

  window.Topology = { build, update };
})();
