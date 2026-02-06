/**
 * Security Metrics Frontend Integration
 * Fetches and displays total requests, threats blocked, and top threat vector from database
 */

const SECURITY_METRICS_API_URL = 'http://localhost:8000/api/security/metrics';
const SECURITY_UPDATE_INTERVAL_MS = 5000; // Update every 5 seconds

/**
 * Fetch security metrics from database
 */
async function fetchSecurityMetrics() {
    try {
        const response = await fetch(SECURITY_METRICS_API_URL);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        return data;

    } catch (error) {
        console.error('Error fetching security metrics:', error);
        return null;
    }
}

/**
 * Update the dashboard metric cards and charts with database values
 */
function updateSecurityMetricsCards(metrics) {
    if (!metrics) {
        console.warn('No security metrics data available');
        return;
    }

    // 1. Update Metric Cards
    const metricCards = document.querySelectorAll('.metric-card');
    if (metricCards.length >= 4) {
        // Card 0: Total Requests
        updateMetricCard(metricCards[0], metrics.total_requests, 'neutral');

        // Card 1: Threats Blocked
        updateMetricCard(metricCards[1], metrics.threats_blocked, 'negative');

        // Card 3: Top Threat Vector
        updateThreatVectorCard(metricCards[3], metrics.top_threat_vector);
    }

    // 2. Update Threat Distribution Chart
    updateThreatDistributionChart(metrics);

    // Log to console
    console.log('📊 Security Metrics Updated from Database:', {
        total_requests: metrics.total_requests,
        threats_blocked: metrics.threats_blocked,
        block_rate: metrics.block_rate + '%',
        top_threat: metrics.top_threat_vector.name,
        threat_count: metrics.top_threat_vector.count,
        vectors_count: metrics.all_threat_vectors.length
    });
}

/**
 * Update a single metric card
 */
function updateMetricCard(card, value, trendClass) {
    const metricValue = card.querySelector('.metric-value');
    if (metricValue) {
        const currentValue = parseInt(metricValue.textContent.replace(/,/g, '')) || 0;
        animateNumberChange(metricValue, currentValue, value, true);
    }
}

/**
 * Update the top threat vector card (4th card)
 */
function updateThreatVectorCard(card, topThreat) {
    const metricValue = card.querySelector('.metric-value-text');
    const metricTrend = card.querySelector('.metric-trend');

    if (metricValue) {
        if (topThreat.name === "None detected" || topThreat.count === 0) {
            metricValue.textContent = "None";
        } else {
            metricValue.textContent = topThreat.name;
        }
    }

    if (metricTrend) {
        // Determine trend based on severity
        const severityClass = {
            'critical': 'negative',
            'high': 'negative',
            'medium': 'neutral',
            'low': 'neutral'
        }[topThreat.severity] || 'neutral';

        metricTrend.className = `metric-trend ${severityClass}`;

        if (topThreat.count > 0) {
            metricTrend.innerHTML = `<span>!</span> ${topThreat.severity.toUpperCase()}`;
        } else {
            metricTrend.innerHTML = `<span>✓</span> No Threats`;
        }
    }
}

/**
 * Update the Threat Distribution Donut Chart and its Legend
 */
function updateThreatDistributionChart(metrics) {
    // Look for Chart.js instance using the global Chart object
    // Chart.getChart is only available in Chart.js v3+
    let chartInstance;
    try {
        chartInstance = Chart.getChart("threatChart");
    } catch (e) {
        console.warn("Chart.getChart failed, trying manual lookup", e);
        // Fallback: look through all instances if getChart is not supported
        Chart.instances.forEach(instance => {
            if (instance.canvas.id === "threatChart") chartInstance = instance;
        });
    }

    if (!chartInstance) {
        console.warn("Threat chart instance not found yet. Retrying later.");
        return;
    }

    const threatVectors = metrics.all_threat_vectors;
    if (!threatVectors || threatVectors.length === 0) {
        return;
    }

    // Prepare data for Chart.js
    const labels = threatVectors.map(v => v.threat_type);
    const counts = threatVectors.map(v => v.count);

    // Update Chart data and labels
    chartInstance.data.labels = labels;
    chartInstance.data.datasets[0].data = counts;
    chartInstance.update();

    // Update Legend in HTML
    const legendContainer = document.querySelector('.chart-legend');
    if (legendContainer) {
        const totalThreats = counts.reduce((a, b) => a + b, 0);
        legendContainer.innerHTML = ''; // Clear current static legend

        // Map of colors to match the chart colors (from script.js)
        const colors = ['#EF4444', '#F97316', '#EAB308', '#3B82F6', '#10B981', '#6366F1', '#EC4899'];

        threatVectors.forEach((vector, index) => {
            const percentage = totalThreats > 0 ? ((vector.count / totalThreats) * 100).toFixed(0) : 0;
            const color = colors[index % colors.length];

            const legendItem = document.createElement('div');
            legendItem.className = 'legend-item';
            legendItem.innerHTML = `
                <span class="legend-dot" style="background: ${color};"></span>
                <span>${vector.threat_type}</span>
                <span class="legend-value">${percentage}%</span>
            `;
            legendContainer.appendChild(legendItem);
        });
    }
}

/**
 * Animate number change with optional comma formatting
 */
function animateNumberChange(element, startValue, endValue, useCommas = false) {
    const duration = 500;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOut = 1 - Math.pow(1 - progress, 3);

        const currentValue = startValue + (endValue - startValue) * easeOut;
        const displayValue = Math.round(currentValue);

        if (useCommas) {
            element.textContent = displayValue.toLocaleString();
        } else {
            element.textContent = displayValue;
        }

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

/**
 * Start periodic security metrics updates
 */
function startSecurityMetricsUpdates() {
    // Initial fetch
    fetchSecurityMetrics().then(updateSecurityMetricsCards);

    // Set up periodic updates
    setInterval(async () => {
        const metrics = await fetchSecurityMetrics();
        updateSecurityMetricsCards(metrics);
    }, SECURITY_UPDATE_INTERVAL_MS);

    console.log(`✅ Security metrics auto-update started (every ${SECURITY_UPDATE_INTERVAL_MS / 1000}s)`);
}

/**
 * Simulate threat detection for demo purposes
 */
async function simulateThreatDetection(threatType, severity = "high", blocked = true) {
    try {
        const response = await fetch('http://localhost:8000/api/security/record-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_type: threatType, severity: severity, blocked: blocked })
        });

        if (response.ok) {
            console.log(`✅ Threat recorded: ${threatType}`);
            const metrics = await fetchSecurityMetrics();
            updateSecurityMetricsCards(metrics);
        }
    } catch (error) {
        console.error('Error recording threat:', error);
    }
}

/**
 * Simulate clean request for demo purposes
 */
async function simulateCleanRequest() {
    try {
        await fetch('http://localhost:8000/api/security/record-request', {
            method: 'POST'
        });

        const metrics = await fetchSecurityMetrics();
        updateSecurityMetricsCards(metrics);
    } catch (error) {
        console.error('Error recording request:', error);
    }
}

// Start auto-updates when page loads
window.addEventListener('DOMContentLoaded', () => {
    // Wait for script.js to initialize the charts
    setTimeout(() => {
        const metricCards = document.querySelectorAll('.metric-card');
        if (metricCards.length > 0) {
            console.log('🚀 Initializing security metrics from database...');
            startSecurityMetricsUpdates();
        }
    }, 1500); // 1.5s delay to be safe
});

/**
 * Utility: Manually update security metrics
 */
window.updateSecurityMetrics = async function () {
    const metrics = await fetchSecurityMetrics();
    updateSecurityMetricsCards(metrics);
};

/**
 * Utility: Populate demo data
 */
window.populateDemoMetrics = async function () {
    console.log('🔄 Populating demo security metrics...');

    const threatTypes = [
        { type: "DAN Attacks", severity: "critical" },
        { type: "Jailbreak", severity: "high" },
        { type: "Roleplay", severity: "high" },
        { type: "Obfuscation", severity: "medium" },
        { type: "System Prompt Leak", severity: "critical" },
        { type: "Direct Injection", severity: "high" }
    ];

    for (let i = 0; i < 50; i++) {
        if (i < 20) {
            const threat = threatTypes[i % threatTypes.length];
            await simulateThreatDetection(threat.type, threat.severity, true);
        } else {
            await simulateCleanRequest();
        }
        await new Promise(resolve => setTimeout(resolve, 30));
    }

    console.log('✅ Demo data populated!');
};

/**
 * Utility: Reset all metrics
 */
window.resetMetrics = async function () {
    if (!confirm('⚠️ Reset ALL security metrics?')) return;

    try {
        const response = await fetch('http://localhost:8000/api/security/reset', { method: 'POST' });
        if (response.ok) {
            const metrics = await fetchSecurityMetrics();
            updateSecurityMetricsCards(metrics);
        }
    } catch (error) {
        console.error('Error resetting metrics:', error);
    }
};
