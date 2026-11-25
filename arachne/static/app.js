"use strict";

const runsElement = document.querySelector("#runs");
const statusElement = document.querySelector("#status");
const caseElement = document.querySelector("#case");
const filter = document.querySelector("#filter");
const integrityContent = document.querySelector("#integrity-content");
const casesTab = document.querySelector("#cases-tab");
const integrityTab = document.querySelector("#integrity-tab");
const decisions = { close: "Закрыть", review: "Запросить данные", escalate: "Эскалировать" };
const checks = { change_record: "Журнал изменений", identity_record: "Сведения об учётной записи",
  activity_record: "Последовательность событий" };
const states = { supports: "Подтверждает штатную версию", disputes: "Указывает на риск",
  conflict: "Источники расходятся", unknown: "Данных недостаточно" };
let runs = [];
let selection;
let requestSequence = 0;
let session = { operator: false };

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

function roleTimeline(runtime) {
  const labels = { red: "Red", blue: "Blue", control: "Независимый рецензент" };
  const phases = { forecast: "Зафиксировал прогноз", select: "Выбрал проверку",
    assess: "Сформулировал гипотезы", reconsider: "Проверил вывод", compare: "Сверил прогноз с исходом" };
  const panel = node("section", undefined, "card");
  const timeline = node("ol");
  for (const step of runtime.trace) {
    if (step.replaced_worker) {
      timeline.append(node("li", labels[step.role] + " · Новый процесс подтвердил прежние ответы"));
    }
    timeline.append(node("li", labels[step.role] + " · " + (phases[step.phase] || step.phase)));
  }
  panel.append(node("h3", "Обмен между агентами"), timeline);
  return panel;
}

function outcomePanel(report) {
  const panel = node("section", undefined, "card");
  if (report.outcome) {
    panel.append(node("h3", "Подтверждённый исход"), node("strong", decisions[report.outcome.decision]),
      node("p", report.outcome.note), node("small", formatTime(report.outcome.created) + " UTC"));
    return panel;
  }
  if (!session.operator || report.scenario) return null;
  const form = node("form", undefined, "outcome-form");
  const select = node("select");
  select.id = "review-decision";
  for (const [key, name] of Object.entries(decisions)) {
    const option = node("option", name);
    option.value = key;
    select.append(option);
  }
  select.value = report.recommendation?.decision ?? "review";
  const decisionLabel = node("label", "Решение оператора");
  decisionLabel.htmlFor = select.id;
  const note = node("textarea");
  note.id = "review-note";
  note.maxLength = 2000;
  note.required = true;
  note.rows = 3;
  const noteLabel = node("label", "На чём основан вывод");
  noteLabel.htmlFor = note.id;
  const save = node("button", "Подтвердить исход");
  save.type = "submit";
  const feedback = node("p");
  feedback.setAttribute("role", "status");
  form.append(decisionLabel, select, noteLabel, note, save, feedback);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const response = await fetch("/api/runs/" + report.id + "/outcome", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Arachne-Operator": session.csrf },
        body: JSON.stringify({ decision: select.value, note: note.value })
      });
      if (!response.ok) throw new Error(response.status === 409
        ? "Исход уже подтверждён. Открой расследование заново." : "Не удалось сохранить исход.");
      if (selection === report.id) await display(report.id);
      await refreshStatus();
    } catch (error) {
      feedback.textContent = error.message;
      save.disabled = false;
    }
  });
  panel.append(node("h3", "Проверка оператором"), form);
  return panel;
}

function sessionCard(scope, indices) {
  const panel = node("section", undefined, "card");
  const status = scope.status === "bound"
    ? "Сеанс связан с журналом аудита Linux."
    : "В журнале нет идентификатора сеанса. Активность нельзя надёжно связать с этим входом.";
  panel.append(node("h3", "Привязка к сеансу"), node("p", status),
    node("small", "Связано " + scope.linked.length + " · Контекст " + scope.context.length
      + " · Исключено " + scope.excluded.length));
  const references = evidence(scope.excluded, indices);
  if (references) panel.append(node("small", "Улики вне сеанса " + references, "mismatch"));
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
  if (report.forecast.decision_distribution) {
    const probabilities = Object.entries(report.forecast.decision_distribution)
      .map(([key, chance]) => decisions[key] + " " + Math.round(chance * 100) + "%");
    forecast.append(node("small", probabilities.join(" · ")));
  }
  const cards = node("div", undefined, "cards");
  cards.append(decisionCard("Blue", report.blue, indices, report.label),
    decisionCard("Обычная проверка", report.standard_review, indices, report.label),
    decisionCard("Blue с прогнозом Red", report.assisted, indices, report.label));
  const timeline = node("ol", undefined, "timeline");
  for (const event of report.events) {
    const item = node("li");
    item.append(node("span", "E" + indices.get(event.id), "event-number"),
      node("div", (event.kind === "privilege_denial_unverified" ? "Отказ sudo без подтверждённого источника" : event.kind)
        + " · " + event.actor), node("small", formatTime(event.timestamp) + " UTC · " + event.source));
    if (report.session_attribution?.excluded.includes(event.id)) {
      item.append(node("small", "Вне сеанса · не учтено в решении", "mismatch"));
    }
    if (report.provenance?.unverified.includes(event.id)) {
      item.append(node("small", "Подтверждение не прошло проверку источника", "mismatch"));
    } else if (report.provenance && Object.hasOwn(report.provenance.verified, event.id)) {
      item.append(node("small", "Проверено · " + report.provenance.verified[event.id]));
    }
    timeline.append(item);
  }
  caseElement.replaceChildren(heading, subheading, forecast, cards);
  if (report.session_attribution) caseElement.append(sessionCard(report.session_attribution, indices));
  if (report.recommendation) {
    caseElement.append(decisionCard("Защитная рекомендация", report.recommendation, indices));
  }
  if (report.full_evidence_reference) {
    caseElement.append(decisionCard("Правила со всеми проверками", report.full_evidence_reference, indices, report.label));
  }
  if (report.mimicry) caseElement.append(reasoningPanel(report.mimicry, indices));
  if (report.role_runtime?.trace) caseElement.append(roleTimeline(report.role_runtime));
  if (report.initial_hypotheses) {
    const hypotheses = node("section", undefined, "card");
    hypotheses.append(node("h3", "Гипотезы Blue"), node("p", report.initial_hypotheses.legitimate),
      node("p", report.initial_hypotheses.security));
    caseElement.append(hypotheses);
  }
  if (report.history_used?.length) {
    caseElement.append(node("p", "Сопоставленные подтверждённые эпизоды · " + report.history_used.length, "muted"));
  }
  const outcome = outcomePanel(report);
  if (outcome) caseElement.append(outcome);
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

async function refreshStatus() {
  const status = await read("/api/status");
  const fields = [
    "События " + status.events, "Реальные досье " + status.investigations,
    "Подтверждено " + status.confirmed, "Проверено записей " + status.authenticated_records,
    "Исключено из авторазбора " + status.excluded_anchors,
    "Ожидают повтора " + status.pending_role_retries
  ];
  fields.push(status.collector ? "Сбор проверен " + formatTime(status.collector.checked_at) + " UTC" : "Ожидание запуска сборщика");
  const missing = status.collector?.coverage?.missing_executable;
  if (missing) fields.push("Без пути к программе в последнем сборе " + missing);
  document.querySelector("#collector-status").textContent = fields.join(" · ");
}

async function boot() {
  try {
    [session] = await Promise.all([read("/api/session"), refreshStatus()]);
    await refresh();
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

const changes = { added: "Добавлен", removed: "Удалён", content: "Изменилось содержимое",
  permissions: "Изменились права", type: "Изменился тип", restored: "Вернулся к исходному состоянию" };

function fileState(entry) {
  if (!entry) return "Отсутствует";
  const mode = entry.mode.toString(8).padStart(4, "0");
  return entry.sha256 ? entry.sha256 + " · " + mode : "Специальный файл · " + mode;
}

async function refreshIntegrity() {
  integrityContent.replaceChildren(node("p", "Загрузка…"));
  try {
    const { baselines, findings } = await read("/api/integrity");
    if (!baselines.length) {
      integrityContent.replaceChildren(node("p", "Папки для наблюдения пока не настроены."));
      return;
    }
    const monitors = node("div", undefined, "cards");
    for (const baseline of baselines) {
      const item = node("section", undefined, "card");
      const status = baseline.complete === null ? "Исходное состояние сохранено" :
        baseline.complete ? "Проверка завершена" : "Проверка не завершена";
      item.append(node("h3", baseline.name), node("p", status, baseline.complete === false ? "mismatch" : undefined),
        node("small", formatTime(baseline.latest_attempt || baseline.last_checked) + " UTC"));
      if (baseline.reason) item.append(node("p", baseline.reason));
      monitors.append(item);
    }
    const log = node("div", undefined, "file-changes");
    for (const finding of findings) {
      const item = node("details", undefined, "card");
      item.append(node("summary", finding.path + " · " + changes[finding.change]),
        node("small", finding.baseline + " · " + formatTime(finding.created) + " UTC"),
        node("p", "Было · " + fileState(finding.previous)), node("p", "Стало · " + fileState(finding.observed)));
      log.append(item);
    }
    integrityContent.replaceChildren(monitors,
      findings.length ? node("h3", "Замеченные изменения") : node("p", "Изменений пока нет."), log);
  } catch (error) {
    integrityContent.replaceChildren(node("p", error.message));
  }
}

function switchView(integrity) {
  document.querySelector("#cases-view").hidden = integrity;
  document.querySelector("#integrity-view").hidden = !integrity;
  casesTab.setAttribute("aria-pressed", String(!integrity));
  integrityTab.setAttribute("aria-pressed", String(integrity));
  if (integrity) refreshIntegrity();
}

casesTab.addEventListener("click", () => switchView(false));
integrityTab.addEventListener("click", () => switchView(true));
document.querySelector("#integrity-reload").addEventListener("click", refreshIntegrity);
filter.addEventListener("input", renderList);
document.querySelector("#reload").addEventListener("click", boot);
boot();
