/**
 * All Alerts Page - JavaScript
 * Handles filtering, search, pagination, and modal display
 */

let allAlerts = [];
let currentPage = 1;
const alertsPerPage = 10;
let filteredAlerts = [];

// Fetch alerts from backend
async function fetchAlerts() {
    try {
        const response = await fetch('/api/security/alerts');
        if (!response.ok) throw new Error('Failed to fetch alerts');
        const data = await response.json();
        return data; // Backend returns nicely formatted alerts
    } catch (error) {
        console.error('Error loading alerts:', error);
        return [];
    }
}

// Initialize
(async () => {
    allAlerts = await fetchAlerts();
    filteredAlerts = [...allAlerts];
    renderAlerts();
})();

// Format timestamp
function formatTimestamp(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// Render alerts table
function renderAlerts() {
    const tbody = document.getElementById('allAlertsBody');
    const start = (currentPage - 1) * alertsPerPage;
    const end = start + alertsPerPage;
    const pageAlerts = filteredAlerts.slice(start, end);

    tbody.innerHTML = pageAlerts.map(alert => `
        <tr class="alert-row severity-${alert.severity}">
            <td style="font-family: monospace; color: #3B82F6;">${alert.id}</td>
            <td class="timestamp">${formatTimestamp(alert.timestamp)}</td>
            <td class="attack-type">
                <span class="badge badge-${alert.severity}">${alert.attackType}</span>
            </td>
            <td class="severity">
                <span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
            </td>
            <td class="prompt-preview">${alert.prompt}</td>
            <td class="source-ip">${alert.sourceIp}</td>
            <td class="status">
                <span class="status-badge status-${alert.status}">${alert.status.toUpperCase()}</span>
            </td>
            <td>
                <button class="page-btn btn-success" onclick="viewAlertDetails('${alert.id}')" style="padding: 0.25rem 0.75rem; font-size: 0.75rem;">
                    View
                </button>
            </td>
        </tr>
    `).join('');

    updatePagination();
}

// Update pagination
function updatePagination() {
    const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
    document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages}`;
    document.getElementById('prevBtn').disabled = currentPage === 1;
    document.getElementById('nextBtn').disabled = currentPage === totalPages;
}

// Change page
function changePage(delta) {
    currentPage += delta;
    renderAlerts();
}

// Apply filters
function applyFilters() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const severityFilter = document.getElementById('severityFilter').value;
    const typeFilter = document.getElementById('typeFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;

    filteredAlerts = allAlerts.filter(alert => {
        const matchesSearch = !searchTerm ||
            alert.prompt.toLowerCase().includes(searchTerm) ||
            alert.sourceIp.includes(searchTerm) ||
            alert.attackType.toLowerCase().includes(searchTerm) ||
            alert.id.toLowerCase().includes(searchTerm);

        const matchesSeverity = !severityFilter || alert.severity === severityFilter;
        const matchesType = !typeFilter || alert.attackType === typeFilter;
        const matchesStatus = !statusFilter || alert.status === statusFilter;

        return matchesSearch && matchesSeverity && matchesType && matchesStatus;
    });

    currentPage = 1;
    renderAlerts();
}

// View alert details
function viewAlertDetails(alertId) {
    const alert = allAlerts.find(a => a.id === alertId);
    if (!alert) return;

    const modal = document.getElementById('alertModal');
    const modalBody = document.getElementById('modalBody');

    modalBody.innerHTML = `
        <div class="detail-grid">
            <div class="detail-label">Alert ID:</div>
            <div class="detail-value" style="font-family: monospace; color: #3B82F6;">${alert.id}</div>

            <div class="detail-label">Timestamp:</div>
            <div class="detail-value">${formatTimestamp(alert.timestamp)}</div>

            <div class="detail-label">Attack Type:</div>
            <div class="detail-value">
                <span class="badge badge-${alert.severity}">${alert.attackType}</span>
            </div>

            <div class="detail-label">Severity:</div>
            <div class="detail-value">
                <span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
            </div>

            <div class="detail-label">Source IP:</div>
            <div class="detail-value" style="font-family: monospace;">${alert.sourceIp}</div>

            <div class="detail-label">Status:</div>
            <div class="detail-value">
                <span class="status-badge status-${alert.status}">${alert.status.toUpperCase()}</span>
            </div>

            <div class="detail-label">Confidence:</div>
            <div class="detail-value">${alert.confidence}</div>

            <div class="detail-label">User Agent:</div>
            <div class="detail-value" style="font-size: 0.75rem;">${alert.userAgent}</div>
        </div>

        <div style="margin-top: 1.5rem;">
            <div class="detail-label" style="margin-bottom: 0.5rem;">Full Prompt:</div>
            <div class="full-prompt">${alert.fullPrompt}</div>
        </div>
    `;

    modal.style.display = 'flex';
}

// Close modal
function closeModal() {
    document.getElementById('alertModal').style.display = 'none';
}

// Export alerts
function exportAlerts(format) {
    if (format === 'csv') {
        exportCSV();
    } else if (format === 'json') {
        exportJSON();
    }
}

function exportCSV() {
    const headers = ['ID', 'Timestamp', 'Attack Type', 'Severity', 'Prompt', 'Source IP', 'Status'];
    const rows = filteredAlerts.map(alert => [
        alert.id,
        formatTimestamp(alert.timestamp),
        alert.attackType,
        alert.severity,
        `"${alert.prompt.replace(/"/g, '""')}"`,
        alert.sourceIp,
        alert.status
    ]);

    const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
    downloadFile(csv, 'alerts.csv', 'text/csv');
}

function exportJSON() {
    const json = JSON.stringify(filteredAlerts, null, 2);
    downloadFile(json, 'alerts.json', 'application/json');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Event listeners
document.getElementById('searchInput').addEventListener('input', applyFilters);
document.getElementById('severityFilter').addEventListener('change', applyFilters);
document.getElementById('typeFilter').addEventListener('change', applyFilters);
document.getElementById('statusFilter').addEventListener('change', applyFilters);
document.getElementById('timeFilter').addEventListener('change', applyFilters);

// Close modal when clicking outside
document.getElementById('alertModal').addEventListener('click', function (e) {
    if (e.target === this) {
        closeModal();
    }
});

// Initial render
renderAlerts();
