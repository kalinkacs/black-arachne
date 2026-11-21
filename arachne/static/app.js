"use strict";

const runsElement = document.querySelector("#runs");
const statusElement = document.querySelector("#status");
const caseElement = document.querySelector("#case");
const filter = document.querySelector("#filter");
const decisions = { close: "Закрыть", review: "Запросить данные", escalate: "Эскалировать" };
let runs = [];
let selection;
let requestSequence = 0;

function node(tag, value, className) {
  const element = document.createElement(tag);
  if (value !== undefined) element.textContent = value;
  if (className) element.className = className;
  return element;
}

async function read(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error("Не удалось загрузить данные.");
  return response.json();
}

function formatTime(value) {
  return new Date(value).toLocaleString("ru-RU", { timeZone: "UTC" });
}

function renderList() {
  const query = filter.value.toLocaleLowerCase().trim();
  const matching = runs.filter((run) => run.host.toLocaleLowerCase().includes(query));
  statusElement.textContent = matching.length ? "" : "Расследования не найдены.";
  runsElement.replaceChildren(...matching.map((run) => {
    const item = node("li");
    const button = node("button", undefined, "run");
    button.type = "button";
    button.setAttribute("aria-pressed", String(run.id === selection));
    button.append(node("strong", run.host), node("small", formatTime(run.created) + " UTC"));
    button.addEventListener("click", () => display(run.id));
    item.append(button);
    return item;
  }));
}

function evidence(ids, indices) {
  return ids.map((id) => indices.get(id)).filter(Boolean).map((number) => "E" + number).join(", ");
}

function decisionCard(title, finding, indices) {
  const element = node("section", undefined, "card");
  element.append(node("h3", title), node("strong", decisions[finding.decision], "decision"),
    node("p", finding.reason), node("small", "Улики " + evidence(finding.evidence_ids, indices)));
  return element;
}

function render(report) {
  const indices = new Map(report.events.map((event, i) => [event.id, i + 1]));
  const heading = node("h2", report.host);
  const subheading = node("p", (report.scenario ? "Лабораторный эпизод · " : "Linux · ") + formatTime(report.created) + " UTC", "muted");
  const forecast = node("section", undefined, "forecast");
  const verification = report.prediction_matched === null ? "Без прогноза" : report.prediction_matched ? "Прогноз совпал" : "Прогноз расходится";
  forecast.append(node("h3", "Прогноз Red"),
    node("p", report.forecast.hypothesis),
    node("small", [report.forecast.engine, decisions[report.forecast.prediction], verification,
      "Улики " + evidence(report.forecast.evidence_ids, indices)].filter(Boolean).join(" · ")));
  const cards = node("div", undefined, "cards");
  cards.append(decisionCard("Blue", report.blue, indices), decisionCard("Обычная проверка", report.standard_review, indices),
    decisionCard("Blue с прогнозом Red", report.assisted, indices));
  const timeline = node("ol", undefined, "timeline");
  for (const event of report.events) {
    const item = node("li");
    item.append(node("span", "E" + indices.get(event.id), "event-number"),
      node("div", event.kind + " · " + event.actor), node("small", formatTime(event.timestamp) + " UTC · " + event.source));
    timeline.append(item);
  }
  caseElement.replaceChildren(heading, subheading, forecast, cards);
  if (report.label) caseElement.append(node("p", "Ожидаемое решение · " + decisions[report.label], "muted"));
  caseElement.append(node("h3", "Хронология улик"), timeline);
}

async function display(id) {
  selection = id;
  const sequence = ++requestSequence;
  renderList();
  caseElement.replaceChildren(node("p", "Загрузка расследования…"));
  try {
    const report = await read("/api/runs/" + id);
    if (requestSequence === sequence) render(report);
  } catch (error) {
    if (requestSequence === sequence) caseElement.replaceChildren(node("p", error.message));
  }
}

async function refresh() {
  try {
    runs = await read("/api/runs");
    renderList();
    if (runs.length && !selection) await display(runs[0].id);
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

filter.addEventListener("input", renderList);
document.querySelector("#reload").addEventListener("click", refresh);
refresh();
