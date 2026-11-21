"use strict";

const runsElement = document.querySelector("#runs");
const statusElement = document.querySelector("#status");
const caseElement = document.querySelector("#case");
const filter = document.querySelector("#filter");
const decisions = { close: "Закрыть", review: "Запросить данные", escalate: "Эскалировать" };
const checks = { change_record: "Журнал изменений", identity_record: "Сведения об учётной записи",
  activity_record: "Последовательность событий" };
const states = { supports: "Подтверждает штатную версию", disputes: "Указывает на риск",
  conflict: "Источники расходятся", unknown: "Данных недостаточно" };
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
  const matching = runs.filter((run) => [run.host, run.scenario || ""].some((value) => value.toLocaleLowerCase().includes(query)));
  statusElement.textContent = matching.length ? "" : "Расследования не найдены.";
  runsElement.replaceChildren(...matching.map((run) => {
    const item = node("li");
    const button = node("button", undefined, "run");
    button.type = "button";
    button.setAttribute("aria-pressed", String(run.id === selection));
    button.append(node("strong", run.scenario || run.host), node("small", formatTime(run.created) + " UTC"));
    if (run.label && run.assisted?.decision !== run.label) button.append(node("small", "Решение Red/Blue расходится с разметкой", "mismatch"));
    button.addEventListener("click", () => display(run.id));
    item.append(button);
    return item;
  }));
}

function evidence(ids, indices) {
  return ids.map((id) => indices.get(id)).filter(Boolean).map((number) => "E" + number).join(", ");
}

function decisionCard(title, finding, indices, expected) {
  const element = node("section", undefined, "card");
  const links = evidence(finding.evidence_ids, indices);
  element.append(node("h3", title), node("strong", decisions[finding.decision], "decision"), node("p", finding.reason));
  if (links) element.append(node("small", "Улики " + links));
  if (expected && expected !== finding.decision) element.append(node("small", "Расходится с разметкой", "mismatch"));
  return element;
}

function reasoningPanel(trace, indices) {
  const panel = node("section", undefined, "card");
  panel.append(node("h3", "Что предполагали и что нашли"));
  for (const [title, observation] of [
    ["Обычная проверка", trace.standard_observation], ["Подсказка Red", trace.assisted_observation]
  ]) {
    const refs = evidence(observation.evidence_ids, indices);
    panel.append(node("p", [title, checks[observation.check], states[observation.state], refs].filter(Boolean).join(" · ")));
  }
  for (const [perspective, title] of [["legitimate", "Штатная версия"], ["security", "Версия угрозы"]]) {
    const state = trace.hypotheses[perspective].expectations[trace.assisted_observation.check];
    const match = trace.hypothesis_matches[perspective];
    const result = match === undefined ? "Нельзя проверить по имеющейся улике" : match ? "Ожидание совпало" : "Ожидание расходится";
    panel.append(node("small", title + " · " + states[state] + " · " + result));
  }
  return panel;
}

function render(report) {
  const indices = new Map(report.events.map((event, i) => [event.id, i + 1]));
  const heading = node("h2", report.scenario || report.host);
  const subheading = node("p", (report.scenario ? "Лабораторный эпизод · " : "Linux · ") + formatTime(report.created) + " UTC", "muted");
  const forecast = node("section", undefined, "forecast");
  const verification = report.prediction_matched === null ? "Без прогноза" : report.prediction_matched ? "Прогноз совпал" : "Прогноз расходится";
  const redLinks = evidence(report.forecast.evidence_ids, indices);
  forecast.append(node("h3", "Прогноз Red"),
    node("p", report.forecast.hypothesis),
    node("small", [report.forecast.engine, decisions[report.forecast.prediction], verification,
      redLinks ? "Улики " + redLinks : ""].filter(Boolean).join(" · ")));
  if (report.forecast.disconfirmation) forecast.append(node("small", report.forecast.disconfirmation));
  const cards = node("div", undefined, "cards");
  cards.append(decisionCard("Blue", report.blue, indices, report.label),
    decisionCard("Обычная проверка", report.standard_review, indices, report.label),
    decisionCard("Blue с прогнозом Red", report.assisted, indices, report.label));
  const timeline = node("ol", undefined, "timeline");
  for (const event of report.events) {
    const item = node("li");
    item.append(node("span", "E" + indices.get(event.id), "event-number"),
      node("div", event.kind + " · " + event.actor), node("small", formatTime(event.timestamp) + " UTC · " + event.source));
    timeline.append(item);
  }
  caseElement.replaceChildren(heading, subheading, forecast, cards);
  if (report.recommendation) {
    caseElement.append(decisionCard("Защитная рекомендация", report.recommendation, indices));
  }
  if (report.mimicry) caseElement.append(reasoningPanel(report.mimicry, indices));
  if (report.initial_hypotheses) {
    const hypotheses = node("section", undefined, "card");
    hypotheses.append(node("h3", "Гипотезы Blue"), node("p", report.initial_hypotheses.legitimate),
      node("p", report.initial_hypotheses.security));
    caseElement.append(hypotheses);
  }
  if (report.history_used?.length) {
    caseElement.append(node("p", "Сопоставленные подтверждённые эпизоды · " + report.history_used.length, "muted"));
  }
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
