/* Aegis Analyst Console Client Application */

document.addEventListener("DOMContentLoaded", () => {
    // State management
    const state = {
        activeTab: "overview",
        activeTenant: "default",
        status: {},
        metrics: {},
        approvals: [],
        audit: [],
        allowlist: []
    };

    // DOM Elements
    const elements = {
        navItems: document.querySelectorAll(".nav-item"),
        tabContents: document.querySelectorAll(".tab-content"),
        pageTitle: document.getElementById("page-title"),
        tenantSelect: document.getElementById("tenant-select"),
        
        // Status panel
        dryRun: document.getElementById("status-dryrun"),
        killSwitch: document.getElementById("status-killswitch"),
        integrity: document.getElementById("status-integrity"),

        // KPIs
        kpiFindings: document.getElementById("kpi-findings"),
        kpiPending: document.getElementById("kpi-pending"),
        kpiAutonomous: document.getElementById("kpi-autonomous"),
        kpiHuman: document.getElementById("kpi-human"),
        navPendingBadge: document.getElementById("nav-pending-badge"),
        queuePendingCount: document.getElementById("queue-pending-count"),

        // Lists/Tables
        overviewTimeline: document.getElementById("overview-timeline"),
        overviewEmptyState: document.getElementById("overview-empty-state"),
        queueList: document.getElementById("queue-list"),
        queueEmptyState: document.getElementById("queue-empty-state"),
        auditBody: document.getElementById("audit-table-body"),
        auditSearch: document.getElementById("audit-search"),
        allowlistBody: document.getElementById("allowlist-table-body"),
        promoteForm: document.getElementById("promote-form"),
        promoteClass: document.getElementById("promote-class"),
        promoteReason: document.getElementById("promote-reason"),

        // Modals
        authModal: document.getElementById("auth-modal"),
        modalCloseBtn: document.getElementById("modal-close-btn"),
        modalCancelBtn: document.getElementById("modal-cancel-btn"),
        authForm: document.getElementById("auth-form"),
        modalActionTitle: document.getElementById("modal-action-title"),
        modalTargetId: document.getElementById("modal-target-id"),
        modalActionType: document.getElementById("modal-action-type"),
        modalActionClass: document.getElementById("modal-action-class"),
        modalReasonGroup: document.getElementById("modal-reason-group"),
        authOperatorId: document.getElementById("auth-operator-id"),
        authToken: document.getElementById("auth-token"),
        authReason: document.getElementById("auth-reason")
    };

    // Helper functions
    const formatTime = (ts) => {
        if (!ts) return "N/A";
        // Handles standard epoch ms
        if (typeof ts === "number") {
            return new Date(ts).toLocaleString();
        }
        // Handles ISO string
        try {
            return new Date(ts).toLocaleString();
        } catch {
            return ts;
        }
    };

    const getSeverityClass = (sev) => {
        if (sev >= 9.0) return "critical";
        if (sev >= 7.0) return "high";
        if (sev >= 4.0) return "medium";
        return "low";
    };

    const getSeverityLabel = (sev) => {
        if (sev >= 9.0) return "Critical";
        if (sev >= 7.0) return "High";
        if (sev >= 4.0) return "Medium";
        return "Low";
    };

    // API fetches
    const fetchStatus = async () => {
        try {
            const res = await fetch("/api/status", {
                headers: { "X-Tenant-ID": state.activeTenant }
            });
            state.status = await res.json();
            updateStatusUI();
        } catch (e) {
            console.error("Failed fetching status", e);
        }
    };

    const fetchMetrics = async () => {
        try {
            const res = await fetch("/api/metrics", {
                headers: { "X-Tenant-ID": state.activeTenant }
            });
            state.metrics = await res.json();
            updateMetricsUI();
        } catch (e) {
            console.error("Failed fetching metrics", e);
        }
    };

    const fetchApprovals = async () => {
        try {
            const res = await fetch("/api/approvals", {
                headers: { "X-Tenant-ID": state.activeTenant }
            });
            state.approvals = await res.json();
            updateApprovalsUI();
        } catch (e) {
            console.error("Failed fetching approvals", e);
        }
    };

    const fetchAudit = async () => {
        try {
            const res = await fetch("/api/audit", {
                headers: { "X-Tenant-ID": state.activeTenant }
            });
            state.audit = await res.json();
            updateAuditUI();
        } catch (e) {
            console.error("Failed fetching audit", e);
        }
    };

    const fetchAllowlist = async () => {
        try {
            const res = await fetch("/api/allowlist", {
                headers: { "X-Tenant-ID": state.activeTenant }
            });
            state.allowlist = await res.json();
            updateAllowlistUI();
        } catch (e) {
            console.error("Failed fetching allowlist", e);
        }
    };

    // UI updates
    const updateStatusUI = () => {
        // Dry-run
        if (state.status.dry_run) {
            elements.dryRun.className = "status-indicator";
            elements.dryRun.innerHTML = `<span class="dot yellow"></span> DRY RUN: ACTIVE`;
        } else {
            elements.dryRun.className = "status-indicator";
            elements.dryRun.innerHTML = `<span class="dot green"></span> DRY RUN: REAL DISPATCH`;
        }

        // Killswitch
        if (state.status.kill_switch) {
            elements.killSwitch.className = "status-indicator";
            elements.killSwitch.innerHTML = `<span class="dot red"></span> KILL SWITCH: ENGAGED`;
        } else {
            elements.killSwitch.className = "status-indicator";
            elements.killSwitch.innerHTML = `<span class="dot green"></span> KILL SWITCH: OFF`;
        }

        // Integrity
        if (state.status.integrity_verified) {
            elements.integrity.className = "status-indicator";
            elements.integrity.innerHTML = `<span class="dot green"></span> LOG INTEGRITY: VERIFIED`;
        } else {
            elements.integrity.className = "status-indicator";
            elements.integrity.innerHTML = `<span class="dot red"></span> LOG INTEGRITY: COMPROMISED`;
        }
    };

    const updateMetricsUI = () => {
        elements.kpiFindings.textContent = state.metrics.total_findings || 0;
        elements.kpiPending.textContent = state.metrics.total_pending || 0;
        elements.kpiAutonomous.textContent = state.metrics.total_autonomous_actions || 0;
        elements.kpiHuman.textContent = state.metrics.total_human_overridden_actions || 0;
        
        // Update nav badges
        const pending = state.metrics.total_pending || 0;
        if (pending > 0) {
            elements.navPendingBadge.style.display = "inline-block";
            elements.navPendingBadge.textContent = pending;
            elements.queuePendingCount.textContent = `${pending} Pending`;
        } else {
            elements.navPendingBadge.style.display = "none";
            elements.queuePendingCount.textContent = "0 Pending";
        }
    };

    const updateApprovalsUI = () => {
        const pendingList = state.approvals.filter(a => a.status === "pending");
        if (pendingList.length === 0) {
            elements.queueEmptyState.style.display = "block";
            elements.queueList.innerHTML = "";
            return;
        }

        elements.queueEmptyState.style.display = "none";
        elements.queueList.innerHTML = pendingList.map(req => {
            const plannedCalls = req.planned_api_calls.map(c => `<li>$ ${c}</li>`).join("");
            const techniques = req.mitre_techniques.map(t => `<span class="tech-tag">${t}</span>`).join("");
            const severityClass = getSeverityClass(req.severity);
            const severityLabel = getSeverityLabel(req.severity);

            return `
                <div class="request-card" id="card-${req.request_id}">
                    <div class="request-card-header">
                        <div class="request-meta">
                            <h3>${req.action_class} on <code>${req.target}</code></h3>
                            <p>Request ID: <strong>${req.request_id}</strong> | Ingested: ${formatTime(req.created_at)}</p>
                        </div>
                        <span class="severity-badge ${severityClass}">${severityLabel} (${req.severity})</span>
                    </div>
                    <div class="request-body">
                        <div class="intel-box">
                            <p><strong>Finding Target:</strong> ${req.finding_type} (${req.finding_id})</p>
                            <p><strong>Rationale:</strong> *${req.rationale}*</p>
                            <p><strong>Policy gate reason:</strong> ${req.policy_reason}</p>
                            ${req.threat_intel_summary ? `<p style="margin-top:8px;"><strong>Threat Intelligence:</strong> ${req.threat_intel_summary}</p>` : ""}
                            ${techniques ? `<div style="margin-top: 4px;">${techniques}</div>` : ""}
                            ${req.correlation_summary ? `<p style="margin-top:8px;"><strong>Correlation Analysis:</strong> ${req.correlation_summary}</p>` : ""}
                        </div>
                        
                        <div class="api-box">
                            <strong>Planned containment API operations:</strong>
                            <ul style="margin: 8px 0 0 16px; font-size:13px; font-family:var(--font-code); color:#38bdf8;">
                                ${plannedCalls}
                            </ul>
                            <p style="font-size:12px; margin-top:8px; color:var(--text-muted);">
                                <strong>Rollback logic:</strong> ${req.rollback_hint || "N/A"}
                            </p>
                        </div>
                    </div>
                    <div class="request-actions">
                        <button class="btn btn-primary" onclick="openApprovalModal('${req.request_id}', 'approve')">Approve Action</button>
                        <button class="btn btn-danger" onclick="openApprovalModal('${req.request_id}', 'deny')">Deny / Discard</button>
                    </div>
                </div>
            `;
        }).join("");
    };

    const updateAuditUI = () => {
        if (state.audit.length === 0) {
            elements.auditBody.innerHTML = `<tr><td colspan="4" class="text-center">No audit records found.</td></tr>`;
            elements.overviewTimeline.innerHTML = "";
            elements.overviewEmptyState.style.display = "block";
            return;
        }

        // Render Overview Timeline (Recent 5 events)
        elements.overviewEmptyState.style.display = "none";
        const recentEvents = [...state.audit].reverse().slice(0, 5);
        elements.overviewTimeline.innerHTML = recentEvents.map(event => {
            let stageDesc = "";
            const payload = event.payload || {};
            
            if (event.stage === "triage") {
                stageDesc = `Assessed ${payload.threat_category} | Severity ${payload.severity} | *${payload.justification}*`;
            } else if (event.stage === "policy") {
                const action = payload.action || {};
                const decision = payload.decision || {};
                stageDesc = `Evaluated ${action.action_class} on ${action.target} | Disposition: **${decision.disposition}** (${decision.reason})`;
            } else if (event.stage === "containment") {
                stageDesc = `Executed ${payload.action_class} on ${payload.target} | Status: **${payload.executed ? 'Executed' : 'Dry-Run/Pending'}** (${payload.detail})`;
            } else if (event.stage === "approval") {
                stageDesc = `Human ${payload.decision} for ${payload.action_class} on ${payload.target} by **${payload.operator_id}**`;
            } else if (event.stage === "governance") {
                stageDesc = `Allowlist modification: ${payload.decision} of ${payload.action_class} by **${payload.operator_id}**`;
            } else if (event.stage === "threat_intel") {
                stageDesc = `Threat intelligence update: *${payload.threat_intel_summary || payload.intel_summary || ''}*`;
            } else if (event.stage === "correlation") {
                stageDesc = `Correlated campaign findings: *${payload.correlation_summary || ''}*`;
            } else if (event.stage === "forensics") {
                const items = payload.items || [];
                stageDesc = `Preserved evidence: ${items.map(i => i.kind).join(", ")}`;
            } else if (event.stage === "error") {
                stageDesc = `Pipeline failure: *${payload.error}*`;
            } else {
                stageDesc = JSON.stringify(payload);
            }

            return `
                <div class="timeline-item ${event.stage}">
                    <div class="timeline-header">
                        <span class="timeline-title">${event.stage.toUpperCase()} (${event.finding_id})</span>
                        <span class="timeline-time">${formatTime(event.ts)}</span>
                    </div>
                    <div class="timeline-desc">${stageDesc}</div>
                </div>
            `;
        }).join("");

        // Render full Audit explorer table
        renderFilteredAudit(elements.auditSearch.value);
    };

    const renderFilteredAudit = (filterText) => {
        const query = filterText.toLowerCase().trim();
        const filtered = state.audit.filter(e => {
            return e.finding_id.toLowerCase().includes(query) || 
                   e.stage.toLowerCase().includes(query) ||
                   JSON.stringify(e.payload).toLowerCase().includes(query);
        });

        if (filtered.length === 0) {
            elements.auditBody.innerHTML = `<tr><td colspan="4" class="text-center">No matching audit records found.</td></tr>`;
            return;
        }

        elements.auditBody.innerHTML = filtered.map(event => {
            return `
                <tr>
                    <td style="font-family:var(--font-code); font-size:12px; color:var(--text-secondary); white-space:nowrap;">${formatTime(event.ts)}</td>
                    <td><code>${event.finding_id}</code></td>
                    <td><span class="severity-badge ${event.stage === 'error' ? 'critical' : 'medium'}" style="text-transform:uppercase; font-size:11px;">${event.stage}</span></td>
                    <td style="font-size:13px; color:var(--text-secondary); max-width: 500px; overflow-wrap: break-word;"><pre style="font-family:var(--font-code); background:none; padding:0; overflow-x:auto;">${JSON.stringify(event.payload, null, 2)}</pre></td>
                </tr>
            `;
        }).join("");
    };

    const updateAllowlistUI = () => {
        if (state.allowlist.length === 0) {
            elements.allowlistBody.innerHTML = `<tr><td colspan="5" class="text-center">No allowlist entries configured.</td></tr>`;
            return;
        }

        elements.allowlistBody.innerHTML = state.allowlist.map(ac => {
            const domain = ac.startsWith("isolate_pod") || ac.startsWith("cordon_node") || ac.startsWith("delete_pod") || ac.startsWith("scale_deployment_zero") ? "Kubernetes" : "AWS";
            const blastRadius = ac.startsWith("block_ip") || ac.startsWith("cordon_node") ? "Subnet" : (ac.startsWith("attach_deny_all_to_principal") || ac.startsWith("revoke_role_sessions") ? "Account" : "Single Resource");
            const reversible = ac.startsWith("terminate_instance") || ac.startsWith("delete_pod") ? "No" : "Yes";

            return `
                <tr>
                    <td><code>${ac}</code></td>
                    <td>${domain}</td>
                    <td>${blastRadius}</td>
                    <td>${reversible}</td>
                    <td>
                        <button class="btn btn-danger btn-small" onclick="openAllowlistModal('${ac}', 'demote')">Demote</button>
                    </td>
                </tr>
            `;
        }).join("");
    };

    // Modal Actions (Exposed to window so HTML onclick attributes can invoke them)
    window.openApprovalModal = (requestId, type) => {
        elements.modalActionTitle.textContent = type === "approve" ? "Authorize Action Execution" : "Reject Action Request";
        elements.modalTargetId.value = requestId;
        elements.modalActionType.value = type;
        elements.modalActionClass.value = "";
        elements.modalReasonGroup.style.display = "flex";
        elements.authReason.required = true;
        
        elements.authOperatorId.value = "";
        elements.authToken.value = "";
        elements.authReason.value = "";

        elements.authModal.classList.add("active");
    };

    window.openAllowlistModal = (actionClass, type) => {
        elements.modalActionTitle.textContent = type === "promote" ? "Promote Class to Autonomous Allowlist" : "Demote Class from Allowlist";
        elements.modalTargetId.value = "_governance";
        elements.modalActionType.value = type;
        elements.modalActionClass.value = actionClass;
        elements.modalReasonGroup.style.display = "flex";
        elements.authReason.required = true;
        
        elements.authOperatorId.value = "";
        elements.authToken.value = "";
        elements.authReason.value = "";

        elements.authModal.classList.add("active");
    };

    // Navigation switching
    elements.navItems.forEach(item => {
        item.addEventListener("click", () => {
            const tabId = item.getAttribute("data-tab");
            
            elements.navItems.forEach(i => i.classList.remove("active"));
            elements.tabContents.forEach(c => c.classList.remove("active"));
            
            item.classList.add("active");
            document.getElementById(`tab-${tabId}`).classList.add("active");
            
            state.activeTab = tabId;
            elements.pageTitle.textContent = item.textContent.trim().split(" ")[1];
            
            refreshData();
        });
    });

    // Modal close events
    const closeModal = () => {
        elements.authModal.classList.remove("active");
    };
    elements.modalCloseBtn.addEventListener("click", closeModal);
    elements.modalCancelBtn.addEventListener("click", closeModal);

    // Form Submissions
    elements.authForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const type = elements.modalActionType.value;
        const targetId = elements.modalTargetId.value;
        const actionClass = elements.modalActionClass.value;
        const operatorId = elements.authOperatorId.value;
        const token = elements.authToken.value;
        const reason = elements.authReason.value;

        const submitBtn = document.getElementById("modal-submit-btn");
        submitBtn.disabled = true;
        submitBtn.textContent = "Processing...";

        try {
            if (type === "approve" || type === "deny") {
                const res = await fetch(`/api/approvals/${targetId}/action`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action: type,
                        operator_id: operatorId,
                        token: token,
                        reason: reason
                    })
                });
                
                const data = await res.json();
                if (res.ok) {
                    alert(`Action completed successfully: ${data.detail || "Executed successfully"}`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Authentication/Authorization failed: ${data.detail}`);
                }
            } else if (type === "promote") {
                const res = await fetch("/api/allowlist/promote", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action_class: actionClass,
                        operator_id: operatorId,
                        token: token,
                        reason: reason
                    })
                });
                
                const data = await res.json();
                if (res.ok) {
                    alert(`Successfully promoted ${actionClass} to allowlist.`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Failed to promote class: ${data.detail}`);
                }
            } else if (type === "demote") {
                const res = await fetch("/api/allowlist/demote", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action_class: actionClass,
                        operator_id: operatorId,
                        token: token,
                        reason: reason
                    })
                });
                
                const data = await res.json();
                if (res.ok) {
                    alert(`Successfully demoted ${actionClass} from allowlist.`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Failed to demote class: ${data.detail}`);
                }
            }
        } catch (error) {
            console.error("Action error", error);
            alert("Network connection error.");
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Submit Decision";
        }
    });

    // Promotion form submit
    elements.promoteForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const actionClass = elements.promoteClass.value;
        const reason = elements.promoteReason.value;
        
        // Reuse OIDC/local prompt auth modal for promotion
        elements.modalActionTitle.textContent = "Authorize Class Promotion";
        elements.modalTargetId.value = "_governance";
        elements.modalActionType.value = "promote";
        elements.modalActionClass.value = actionClass;
        elements.modalReasonGroup.style.display = "flex";
        elements.authReason.required = true;

        elements.authOperatorId.value = "";
        elements.authToken.value = "";
        elements.authReason.value = reason; // Seed justification

        elements.authModal.classList.add("active");
    });

    // Live search
    elements.auditSearch.addEventListener("input", (e) => {
        renderFilteredAudit(e.target.value);
    });

    // Tenant selection listener
    elements.tenantSelect.addEventListener("change", (e) => {
        state.activeTenant = e.target.value;
        refreshData();
    });

    // Refresh orchestration
    const refreshData = () => {
        fetchStatus();
        fetchMetrics();
        
        if (state.activeTab === "overview") {
            fetchAudit();
        } else if (state.activeTab === "queue") {
            fetchApprovals();
        } else if (state.activeTab === "audit") {
            fetchAudit();
        } else if (state.activeTab === "allowlist") {
            fetchAllowlist();
        }
    };

    // Auto-refresh stats every 8 seconds
    setInterval(() => {
        fetchStatus();
        fetchMetrics();
        if (state.activeTab === "overview" || state.activeTab === "queue") {
            refreshData();
        }
    }, 8000);

    // Initial load
    refreshData();
});
