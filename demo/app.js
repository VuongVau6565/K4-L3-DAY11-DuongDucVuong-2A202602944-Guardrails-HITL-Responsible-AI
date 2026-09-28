(() => {
  "use strict";

  document.getElementById("legacy-mock-script")?.remove();

  const promptInput = document.getElementById("prompt-input");
  const promptForm = document.getElementById("prompt-form");
  const targetSelect = document.getElementById("target-select");
  const chatHistory = document.getElementById("chat-history");
  const auditBody = document.getElementById("audit-body");
  const auditDetail = document.getElementById("audit-detail");
  const auditFilter = document.getElementById("audit-filter");
  const sendButton = document.getElementById("send-button");
  const toast = document.getElementById("toast");
  const statusInfo = {
    allow: { label: "Cho qua", className: "allow" },
    block: { label: "Đã chặn", className: "block" },
    redact: { label: "Đã redact", className: "redact" },
    pending: { label: "Chờ người duyệt", className: "pending" },
    not_applicable: { label: "Không áp dụng", className: "neutral" },
    not_checked: { label: "Chưa kiểm tra", className: "neutral" },
    approval_required: { label: "Chờ người duyệt", className: "pending" }
  };
  let entries = [];
  let selectedId = null;
  let toastTimeout;

  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
  const formatTime = (value) => new Intl.DateTimeFormat("vi-VN", {
    hour: "2-digit", minute: "2-digit", second: "2-digit"
  }).format(new Date(value));

  function badge(status) {
    const info = statusInfo[status] || { label: status || "Chưa kiểm tra", className: "neutral" };
    return `<span class="badge ${info.className}">${escapeHtml(info.label)}</span>`;
  }

  function toastMessage(message, isError = false) {
    toast.textContent = message;
    toast.hidden = false;
    toast.style.borderColor = isError ? "#efb5b6" : "#cde7d9";
    toast.style.background = isError ? "#fff4f4" : "#f1fbf5";
    toast.style.color = isError ? "#a52e38" : "#176245";
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => { toast.hidden = true; }, 6000);
  }

  function renderAudit() {
    const filtered = entries.filter((entry) => (
      auditFilter.value === "all" ||
      (auditFilter.value === "block" ? entry.blocked : !entry.blocked)
    ));
    if (!filtered.length) {
      auditBody.innerHTML = '<tr><td colspan="5" class="empty-state">Chưa có yêu cầu phù hợp trong phiên backend.</td></tr>';
      return;
    }
    auditBody.innerHTML = filtered.map((entry) => `
      <tr data-entry-id="${escapeHtml(entry.id)}" class="${entry.id === selectedId ? "selected" : ""}" tabindex="0">
        <td>${formatTime(entry.time)}</td>
        <td class="td-request" title="${escapeHtml(entry.request)}">${escapeHtml(entry.request)}</td>
        <td>${badge(entry.status)}</td>
        <td>${escapeHtml(`${entry.target.toUpperCase()} · ${entry.layer}`)}</td>
        <td>${escapeHtml(entry.duration)} ms</td>
      </tr>`).join("");
  }

  function selectEntry(id) {
    const entry = entries.find((item) => item.id === id);
    if (!entry) return;
    selectedId = id;
    auditDetail.innerHTML = `
      <h3>Chi tiết sự kiện</h3>
      <div class="detail-item"><span class="detail-label">Target · yêu cầu</span><div class="detail-value">${escapeHtml(entry.target.toUpperCase())} · ${escapeHtml(entry.request)}</div></div>
      <div class="detail-item"><span class="detail-label">Trạng thái · lớp xử lý</span><div class="detail-value">${badge(entry.status)} &nbsp; ${escapeHtml(entry.layer)}</div></div>
      <div class="detail-item"><span class="detail-label">Phản hồi model</span><div class="detail-value">${escapeHtml(entry.answer)}</div></div>
      <div class="detail-item"><span class="detail-label">Chi tiết guardrails</span><div class="detail-value">${escapeHtml(entry.detail)}</div></div>
      <div class="detail-item"><span class="detail-label">Thời gian phản hồi</span><div class="detail-value">${escapeHtml(entry.duration)} ms · ${formatTime(entry.time)}</div></div>`;
    renderAudit();
  }

  function setGuard(key, value) {
    const row = document.querySelector(`[data-guard="${key}"] .badge`);
    const info = statusInfo[value] || { label: value || "Chưa kiểm tra", className: "neutral" };
    row.className = `badge ${info.className}`;
    row.textContent = info.label;
  }

  function setFlow(key, status, text) {
    const step = document.querySelector(`[data-flow="${key}"]`);
    step.classList.remove("is-blocked", "is-warning");
    if (status === "block") step.classList.add("is-blocked");
    if (status === "warning") step.classList.add("is-warning");
    step.querySelector("small").textContent = text;
  }

  function updateMetrics(metrics) {
    document.getElementById("metric-total").textContent = String(metrics.total);
    document.getElementById("metric-blocked").textContent = String(metrics.blocked);
    document.getElementById("metric-limited").textContent = String(metrics.limited);
    document.getElementById("metric-protected").textContent = String(metrics.protected);
  }

  function syncState(state) {
    updateMetrics(state.metrics);
    entries = state.audit;
    renderAudit();
    const readiness = state.configuration;
    targetSelect.querySelector('[value="blue"]').title = readiness.blue_ready ? "Đã cấu hình API key" : "Thiếu cấu hình API key";
    targetSelect.querySelector('[value="red"]').title = readiness.red_ready ? "Đã cấu hình API key" : "Thiếu cấu hình API key";
    targetSelect.querySelector('[value="red_advance"]').title = readiness.red_advance_ready ? "Đã cấu hình API key" : "Thiếu cấu hình API key";
  }

  function setGuardsFromResponse(result) {
    const guards = result.guardrails;
    setGuard("rate", guards.rate_limit);
    setGuard("injection", guards.injection_detection);
    setGuard("topic", guards.topic_filter);
    setGuard("output", guards.output_filter);
    setGuard("egress", guards.egress_policy);

    setFlow("user", "allow", "Đã gửi yêu cầu");
    setFlow("rate", guards.rate_limit === "block" ? "block" : "allow",
      guards.rate_limit === "block" ? "Đã chặn" : guards.rate_limit === "not_applicable" ? "Không áp dụng" : "Cho qua");
    const inputBlocked = guards.injection_detection === "block" || guards.topic_filter === "block";
    setFlow("input", inputBlocked ? "block" : "allow",
      inputBlocked ? "Đã chặn" : guards.injection_detection === "not_applicable" ? "Không áp dụng" : "Cho qua");
    setFlow("ai", result.blocked ? "allow" : "allow", result.blocked ? "Không gọi model" : "Đã gọi model");
    setFlow("output", guards.output_filter === "redact" ? "warning" : "allow",
      guards.output_filter === "redact" ? "Đã redact" :
        guards.output_filter === "not_applicable" || guards.output_filter === "not_checked" ? "Không áp dụng" : "Đã kiểm tra");
    setFlow("audit", "allow", "Đã ghi audit");
  }

  function appendMessage(role, message, target, result) {
    const isUser = role === "user";
    const item = document.createElement("div");
    item.className = `chat-message${isUser ? " user" : ""}`;
    const time = new Intl.DateTimeFormat("vi-VN", { hour: "2-digit", minute: "2-digit" }).format(new Date());
    const meta = isUser ? "Bạn" : `${target.toUpperCase()} · ${result?.provider || "Backend"}`;
    const outcome = result ? `<div class="bubble-result">${badge(result.status)} · ${escapeHtml(result.layer)} · ${escapeHtml(result.latency_ms)} ms</div>` : "";
    item.innerHTML = `
      <span class="avatar">${isUser ? "Bạn" : "AI"}</span>
      <div class="bubble-wrap"><div class="message-meta">${escapeHtml(meta)} · ${time}</div>
      <div class="bubble">${escapeHtml(message)}${outcome}</div></div>`;
    chatHistory.append(item);
    chatHistory.scrollTop = chatHistory.scrollHeight;
  }

  async function refreshState() {
    const response = await fetch("/api/state");
    if (!response.ok) throw new Error("Không tải được trạng thái từ backend.");
    syncState(await response.json());
  }

  async function submitMessage(message) {
    const target = targetSelect.value;
    resetGuards();
    appendMessage("user", message, target);
    sendButton.disabled = true;
    sendButton.textContent = "Đang gọi model...";
    setFlow("user", "allow", "Đã gửi yêu cầu");
    setFlow("rate", "allow", target === "blue" ? "Đang kiểm tra" : "Không áp dụng");
    setFlow("input", "allow", "Đang kiểm tra");
    setFlow("ai", "warning", "Đang gọi model");
    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, target })
      });
      const body = await response.json();
      if (!response.ok) {
        const error = new Error(body.detail || "Backend không thể xử lý yêu cầu.");
        error.status = response.status;
        throw error;
      }
      setGuardsFromResponse(body);
      appendMessage("assistant", body.answer, target, body);
      entries.unshift({
        id: body.request_id,
        time: new Date().toISOString(),
        request: message,
        target: body.target,
        status: body.status,
        blocked: body.blocked,
        layer: body.layer,
        duration: body.latency_ms,
        answer: body.answer,
        detail: Object.entries(body.guardrails).map(([key, value]) => `${key}: ${value}`).join(" · ")
      });
      selectedId = body.request_id;
      updateMetricsFromResponse(body);
      renderAudit();
      selectEntry(body.request_id);
      if (body.requires_approval) {
        document.getElementById("hitl-status").className = "badge pending";
        document.getElementById("hitl-status").textContent = "Chờ người duyệt";
        document.getElementById("hitl-note").textContent = "Mô phỏng — không phát sinh giao dịch";
      }
    } catch (error) {
      const messageText = error instanceof TypeError
        ? "Không kết nối được backend. Hãy khởi chạy máy chủ Python tại http://127.0.0.1:8000."
        : error.message;
      appendMessage("assistant", `Lỗi ${error.status || "kết nối"}: ${messageText}`, target);
      toastMessage(messageText, true);
      resetGuards();
    } finally {
      sendButton.disabled = false;
      sendButton.innerHTML = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m21 3-7.2 18-3.9-7.9L2 9.2 21 3Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M10 13 21 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg> Gửi yêu cầu';
    }
  }

  function updateMetricsFromResponse(result) {
    const total = Number(document.getElementById("metric-total").textContent) + 1;
    const blocked = Number(document.getElementById("metric-blocked").textContent) + Number(result.blocked);
    const limited = Number(document.getElementById("metric-limited").textContent) + Number(result.guardrails.rate_limit === "block");
    const protectedCount = Number(document.getElementById("metric-protected").textContent) + Number(result.guardrails.output_filter === "redact");
    updateMetrics({ total, blocked, limited, protected: protectedCount });
  }

  function resetGuards() {
    ["rate", "injection", "topic", "output", "egress"].forEach((key) => setGuard(key, "not_checked"));
    setFlow("user", "allow", "Chờ yêu cầu");
    setFlow("rate", "allow", "Chưa kiểm tra");
    setFlow("input", "allow", "Chưa kiểm tra");
    setFlow("ai", "allow", "Đang chờ");
    setFlow("output", "allow", "Chưa kiểm tra");
    setFlow("audit", "allow", "Chưa ghi");
  }

  document.querySelectorAll(".quick-prompt").forEach((button) => button.addEventListener("click", () => {
    promptInput.value = button.textContent.trim();
    promptInput.focus();
  }));
  promptForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const message = promptInput.value.trim();
    if (!message || sendButton.disabled) {
      promptInput.focus();
      return;
    }
    promptInput.value = "";
    void submitMessage(message);
  });
  auditFilter.addEventListener("change", renderAudit);
  auditBody.addEventListener("click", (event) => {
    const row = event.target.closest("tr[data-entry-id]");
    if (row) selectEntry(row.dataset.entryId);
  });
  auditBody.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const row = event.target.closest("tr[data-entry-id]");
    if (row) {
      event.preventDefault();
      selectEntry(row.dataset.entryId);
    }
  });
  document.getElementById("approve-button").addEventListener("click", () => {
    document.getElementById("hitl-status").className = "badge allow";
    document.getElementById("hitl-status").textContent = "Đã duyệt (demo)";
    document.getElementById("hitl-note").textContent = "Đã duyệt trong mô phỏng — không phát sinh giao dịch";
    toastMessage("Đã ghi nhận phê duyệt trong giao diện demo. Không có giao dịch nào được thực hiện.");
  });
  document.getElementById("reject-button").addEventListener("click", () => {
    document.getElementById("hitl-status").className = "badge block";
    document.getElementById("hitl-status").textContent = "Đã từ chối (demo)";
    document.getElementById("hitl-note").textContent = "Đã từ chối trong mô phỏng — không phát sinh giao dịch";
    toastMessage("Đã ghi nhận từ chối trong giao diện demo. Không có giao dịch nào được thực hiện.");
  });

  resetGuards();
  void refreshState().catch((error) => toastMessage(error.message, true));
})();
