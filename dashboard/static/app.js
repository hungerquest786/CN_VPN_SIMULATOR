// App shell: tabs, the 1-second poll of /api/stats, and the header status.
// To add a page later: write a new file, load it in index.html, and call
//   Dashboard.registerPage({id, title, build(root), onShow(), onHide(), onStats(stats)})
// (onShow/onHide/onStats are optional). Pages are read-only: nothing here sends data to the server.
(function () {
  const pages = [];
  let current = null;
  let lastStats = { running: false };

  // Small DOM helper: el("div", {class: "x"}, "text", childNode). Text is never parsed as HTML.
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v; else n.setAttribute(k, v);
    }
    for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  }

  function setStatus(text, up) {
    document.getElementById("status-text").textContent = text;
    document.getElementById("status").classList.toggle("up", up);
  }

  function showStatus(stats, failed) {
    if (failed) return setStatus("DASHBOARD CANNOT REACH ITS API", false);
    if (!stats.running) return setStatus("NO VPN SERVER RUNNING", false);
    const n = stats.clients.length;
    setStatus(`CONNECTED · ${n} ${n === 1 ? "CLIENT" : "CLIENTS"}`, true);
  }

  async function poll() {
    let failed = false;
    try {
      const r = await fetch("/api/stats", { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      lastStats = await r.json();
    } catch (e) {
      failed = true;
      lastStats = { running: false };
    }
    showStatus(lastStats, failed);
    for (const p of pages) if (p.onStats) p.onStats(lastStats);
  }

  function select(id) {
    const page = pages.find(p => p.id === id) || pages[0];
    if (current === page) return;
    if (current && current.onHide) current.onHide();
    current = page;
    for (const p of pages) {
      p.root.classList.toggle("on", p === page);
      p.tab.classList.toggle("on", p === page);
    }
    history.replaceState(null, "", "#" + page.id);
    if (page.onShow) page.onShow();
  }

  window.Dashboard = {
    el,
    registerPage(p) { pages.push(p); },
  };

  document.addEventListener("DOMContentLoaded", () => {
    const tabs = document.getElementById("tabs");
    const main = document.getElementById("pages");
    for (const p of pages) {
      p.root = el("section", { class: "page" });
      main.append(p.root);
      p.build(p.root);
      p.tab = el("button", { type: "button" }, p.title);
      p.tab.addEventListener("click", () => select(p.id));
      tabs.append(p.tab);
    }
    select(location.hash.slice(1));
    poll();
    setInterval(poll, 1000);
  });
})();
