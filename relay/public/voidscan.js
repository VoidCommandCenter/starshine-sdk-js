const state = {
  ledger: null,
  events: [],
  cursor: "",
  loading: false,
};

const elements = {
  ledgerName: document.querySelector("#ledger-name"),
  ledgerId: document.querySelector("#ledger-id"),
  environment: document.querySelector("#environment"),
  eventCount: document.querySelector("#event-count"),
  latestSequence: document.querySelector("#latest-sequence"),
  events: document.querySelector("#events"),
  empty: document.querySelector("#empty"),
  error: document.querySelector("#error"),
  search: document.querySelector("#search"),
  refresh: document.querySelector("#refresh"),
  loadMore: document.querySelector("#load-more"),
  indexedAt: document.querySelector("#indexed-at"),
  copyLedger: document.querySelector("#copy-ledger"),
  detail: document.querySelector("#detail"),
  closeDetail: document.querySelector("#close-detail"),
  detailBackdrop: document.querySelector("#detail-backdrop"),
  detailLoading: document.querySelector("#detail-loading"),
  detailContent: document.querySelector("#detail-content"),
  eventDetail: document.querySelector("#event-detail"),
  proofDetail: document.querySelector("#proof-detail"),
  certificateDetail: document.querySelector("#certificate-detail"),
};

function short(value, left = 10, right = 7) {
  if (!value) return "—";
  return value.length <= left + right + 1
    ? value
    : `${value.slice(0, left)}…${value.slice(-right)}`;
}

function when(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(date);
}

async function request(path) {
  const response = await fetch(path, { headers: { accept: "application/json" } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function showError(error) {
  elements.error.textContent = error instanceof Error ? error.message : String(error);
  elements.error.hidden = false;
}

function clearError() {
  elements.error.hidden = true;
  elements.error.textContent = "";
}

async function loadLedger() {
  const ledger = await request("/v1/scan/ledger");
  state.ledger = ledger;
  elements.ledgerName.textContent = ledger.name;
  elements.ledgerId.textContent = ledger.ledgerId;
  elements.environment.textContent = ledger.environment;
  document.title = `${ledger.name} · VOIDSCAN`;
}

async function loadEvents({ append = false, quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  elements.refresh.disabled = true;
  elements.loadMore.disabled = true;
  if (!quiet) clearError();
  try {
    const cursor = append && state.cursor ? `&cursor=${encodeURIComponent(state.cursor)}` : "";
    const page = await request(`/v1/scan/events?limit=50${cursor}`);
    state.events = append
      ? [...state.events, ...page.events.filter((event) => !state.events.some((item) => item.eventId === event.eventId))]
      : page.events;
    state.cursor = page.nextCursor;
    elements.eventCount.textContent = Number(page.ledgerEventCount).toLocaleString();
    elements.latestSequence.textContent = state.events[0]?.ledgerSequence || "0";
    elements.indexedAt.textContent = `INDEXED ${when(page.indexedAt)}`;
    elements.loadMore.hidden = !state.cursor;
    renderEvents();
  } catch (error) {
    if (!quiet) showError(error);
  } finally {
    state.loading = false;
    elements.refresh.disabled = false;
    elements.loadMore.disabled = false;
  }
}

function renderEvents() {
  const query = elements.search.value.trim().toLowerCase();
  const events = query
    ? state.events.filter((event) => [
        event.eventId,
        event.eventHash,
        event.artifactRoot,
        event.operation,
        event.ledgerSequence,
      ].join(" ").toLowerCase().includes(query))
    : state.events;
  elements.events.replaceChildren();
  for (const event of events) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.setAttribute("aria-label", `View proof for event ${event.eventId}`);
    row.addEventListener("click", () => openDetail(event.eventId));
    row.addEventListener("keydown", (keyboardEvent) => {
      if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") openDetail(event.eventId);
    });
    row.append(
      cell(event.ledgerSequence, "seq"),
      badgeCell(event.operation),
      cell(short(event.eventId, 12, 8), "mono", event.eventId),
      cell(short(event.eventHash), "mono", event.eventHash),
      cell(when(event.acceptedAt)),
      cell("VERIFY →", "proof-link"),
    );
    elements.events.append(row);
  }
  elements.empty.hidden = events.length !== 0;
}

function cell(text, className, title) {
  const element = document.createElement("td");
  if (className) element.className = className;
  element.textContent = text;
  if (title) element.title = title;
  return element;
}

function badgeCell(operation) {
  const element = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = "operation";
  badge.textContent = operation;
  element.append(badge);
  return element;
}

async function openDetail(eventId) {
  elements.detail.classList.add("open");
  elements.detail.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  elements.detailLoading.hidden = false;
  elements.detailContent.hidden = true;
  try {
    const detail = await request(`/v1/scan/events/${encodeURIComponent(eventId)}`);
    renderDetail(detail);
    elements.detailLoading.hidden = true;
    elements.detailContent.hidden = false;
  } catch (error) {
    elements.detailLoading.textContent = error instanceof Error ? error.message : String(error);
  }
}

function closeDetail() {
  elements.detail.classList.remove("open");
  elements.detail.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  elements.detailLoading.textContent = "Verifying checkpoint proof…";
}

function renderDetail(detail) {
  const event = detail.event;
  const proof = detail.proof;
  const certificate = proof.checkpointCertificate;
  renderDefinitionList(elements.eventDetail, [
    ["Event ID", event.eventId, true],
    ["Operation", event.operation],
    ["Accepted", when(event.acceptedAt)],
    ["Ledger sequence", event.ledgerSequence],
    ["Artifact root", event.artifactRoot, true],
    ["Event hash", event.eventHash, true],
    ["Node ID", event.nodeId, true],
  ]);
  renderDefinitionList(elements.proofDetail, [
    ["Verification", proof.verified ? "VALID" : "INVALID"],
    ["Finality", proof.finality],
    ["Checkpoint height", proof.checkpointHeight],
    ["Ledger event count", proof.ledgerEventCount],
    ["Ledger position", `${proof.ledgerIndex} of ${proof.ledgerCount}`],
    ["Ledger root", proof.ledgerRoot, true],
    ["Ledger commitment", proof.ledgerCommitment, true],
    ["Checkpoint root", proof.checkpointRoot, true],
    ["Ledger path nodes", String(proof.ledgerPath.length)],
    ["Global path nodes", String(proof.globalPath.length)],
  ]);
  renderDefinitionList(elements.certificateDetail, [
    ["Version", String(certificate.version)],
    ["Created", when(certificate.createdAt)],
    ["Checkpoint hash", certificate.checkpointHash, true],
    ["Previous hash", certificate.previousCheckpointHash || "GENESIS", Boolean(certificate.previousCheckpointHash)],
    ["Global root", certificate.globalRoot, true],
    ["Node ID", certificate.nodeId, true],
    ["ML-DSA public key", certificate.nodeMlDsaPublicKey, true],
    ["ML-DSA signature", certificate.nodeMlDsaSignature, true],
  ]);
}

function renderDefinitionList(target, rows) {
  target.replaceChildren();
  for (const [label, value, copyable = false] of rows) {
    const row = document.createElement("div");
    row.className = "detail-row";
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = copyable ? short(String(value), 18, 12) : String(value);
    detail.title = String(value);
    row.append(term, detail);
    if (copyable) {
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "copy-mini";
      copy.textContent = "COPY";
      copy.addEventListener("click", () => copyText(String(value), copy));
      row.append(copy);
    }
    target.append(row);
  }
}

async function copyText(value, button) {
  await navigator.clipboard.writeText(value);
  const previous = button.textContent;
  button.textContent = "COPIED";
  setTimeout(() => { button.textContent = previous; }, 900);
}

elements.search.addEventListener("input", renderEvents);
elements.refresh.addEventListener("click", () => loadEvents());
elements.loadMore.addEventListener("click", () => loadEvents({ append: true }));
elements.closeDetail.addEventListener("click", closeDetail);
elements.detailBackdrop.addEventListener("click", closeDetail);
elements.copyLedger.addEventListener("click", () => {
  if (state.ledger) copyText(state.ledger.ledgerId, elements.copyLedger);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDetail();
});

Promise.all([loadLedger(), loadEvents()]).catch(showError);
setInterval(() => loadEvents({ quiet: true }), 15_000);
