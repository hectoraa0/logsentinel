"use strict";

// Log data is attacker-controlled, so everything is rendered with textContent.
const SEVERITIES = ["critical", "high", "medium", "low"];
let activeFilter = "all";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatTime(iso) {
  return iso.replace("T", " ").replace(/\+00:00$/, "");
}

async function getJSON(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(url + " -> " + response.status);
  return response.json();
}

function renderStats(stats) {
  const box = document.getElementById("stats");
  box.replaceChildren();
  const total = el("div", "card");
  total.append(el("div", "num", String(stats.total)), el("div", "label", "Total alerts"));
  box.append(total);
  for (const sev of SEVERITIES) {
    const card = el("div", "card sev-" + sev);
    card.append(el("div", "num", String(stats.by_severity[sev] || 0)), el("div", "label", sev));
    box.append(card);
  }
  const ips = el("div", "card");
  ips.append(el("div", "num", String(stats.unique_ips)), el("div", "label", "Unique source IPs"));
  box.append(ips);
}

function renderFilters() {
  const box = document.getElementById("filters");
  box.replaceChildren();
  for (const name of ["all", ...SEVERITIES]) {
    const button = el("button", name === activeFilter ? "active" : "", name);
    button.type = "button";
    button.addEventListener("click", () => {
      activeFilter = name;
      renderFilters();
      loadAlerts();
    });
    box.append(button);
  }
}

function renderAlerts(alerts) {
  const body = document.getElementById("alerts");
  body.replaceChildren();
  document.getElementById("empty").hidden = alerts.length > 0;

  for (const a of alerts) {
    const row = el("tr", "sev-" + a.severity);
    const badge = el("span", "badge", a.severity);
    const sevCell = el("td");
    sevCell.append(badge);

    const detail = el("tr", "detail");
    detail.hidden = true;
    const detailCell = el("td");
    detailCell.colSpan = 7;
    detailCell.append(el("p", "desc", a.description));
    const evidence = el("pre", "evidence", a.evidence.join("\n"));
    detailCell.append(evidence);
    detail.append(detailCell);

    row.append(
      sevCell,
      el("td", "", a.rule_id + "  " + a.title),
      el("td", "mono", a.ip),
      el("td", "num", String(a.count)),
      el("td", "", a.mitre),
      el("td", "mono", formatTime(a.first_seen)),
      el("td", "mono", formatTime(a.last_seen))
    );
    row.classList.add("clickable");
    row.addEventListener("click", () => {
      detail.hidden = !detail.hidden;
    });
    body.append(row, detail);
  }
}

async function loadAlerts() {
  const query = activeFilter === "all" ? "" : "?severity=" + encodeURIComponent(activeFilter);
  renderAlerts(await getJSON("/api/alerts" + query));
}

async function init() {
  renderFilters();
  renderStats(await getJSON("/api/stats"));
  await loadAlerts();
}

init().catch((err) => {
  const empty = document.getElementById("empty");
  empty.hidden = false;
  empty.textContent = "Could not load data: " + err.message;
});
