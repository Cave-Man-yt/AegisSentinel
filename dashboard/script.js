// Animate numbers counting up
function animateValue(element, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const value = Math.floor(progress * (end - start) + start);

        // Format number with commas
        if (end >= 1000) {
            element.textContent = (value / 1000).toFixed(1) + 'M';
        } else {
            element.textContent = value.toLocaleString();
        }

        if (progress < 1) {
            window.requestAnimationFrame(step);
        } else {
            if (end >= 1000) {
                element.textContent = (end / 1000).toFixed(1) + 'M';
            } else {
                element.textContent = end.toLocaleString();
            }
        }
    };
    window.requestAnimationFrame(step);
}

// Initialize metric animations
function initMetricAnimations() {
    const metricValues = document.querySelectorAll('.metric-value[data-target]');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !entry.target.classList.contains('animated')) {
                entry.target.classList.add('animated');
                const target = parseInt(entry.target.getAttribute('data-target'));
                animateValue(entry.target, 0, target, 2000);
            }
        });
    }, { threshold: 0.5 });

    metricValues.forEach(value => observer.observe(value));
}

// Initialize Threat Distribution Chart
function initThreatChart() {
    const ctx = document.getElementById('threatChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DAN Attacks', 'Roleplay', 'Obfuscation', 'Injection'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#EF4444',
                    '#F97316',
                    '#EAB308',
                    '#3B82F6'
                ],
                borderWidth: 0,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: {
                        family: 'Inter',
                        size: 14,
                        weight: '600'
                    },
                    bodyFont: {
                        family: 'Inter',
                        size: 13
                    },
                    callbacks: {
                        label: function (context) {
                            return context.label + ': ' + context.parsed + '%';
                        }
                    }
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1500,
                easing: 'easeOutQuart'
            }
        }
    });
}

// Initialize Latency Chart with Real Data
async function initLatencyChart() {
    const ctx = document.getElementById('latencyChart');
    if (!ctx) return;

    // Fetch data
    let chartData = {
        labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
        native: [20, 25, 22, 30, 28, 25],
        secured: [120, 130, 125, 140, 135, 130]
    };

    try {
        const response = await fetch('/metrics/latency');
        const data = await response.json();
        if (data.history) {
            chartData.labels = data.history.labels;
            chartData.native = data.history.native;
            chartData.secured = data.history.secured;
        }
    } catch (e) {
        console.error("Failed to load latency history", e);
    }

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: chartData.labels,
            datasets: [
                {
                    label: 'Native',
                    data: chartData.native,
                    backgroundColor: '#1E293B',
                    borderRadius: 4,
                    barThickness: 30
                },
                {
                    label: 'Secured',
                    data: chartData.secured,
                    backgroundColor: '#3B82F6',
                    borderRadius: 4,
                    barThickness: 30
                }
            ]
        },
        // ... options reused ...
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: { color: '#94A3B8', font: { family: 'Inter', size: 12 }, usePointStyle: true, padding: 15 }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)', padding: 12,
                    callbacks: { label: (c) => c.dataset.label + ': ' + c.parsed.y + 'ms' }
                }
            },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#64748B' } },
                y: { grid: { color: 'rgba(51, 65, 85, 0.3)' }, ticks: { color: '#64748B' }, beginAtZero: true }
            }
        }
    });
}

// ... (Heatmap code omitted/unchanged) ...

// Initialize incidents table with Real Data
async function initIncidentsTable() {
    const incidentsBody = document.getElementById('incidentsBody');
    if (!incidentsBody) return;

    try {
        // Reuse the alerts endpoint
        const response = await fetch('/api/security/alerts');
        const alerts = await response.json();

        // Take top 7
        const incidents = alerts.slice(0, 7).map(a => ({
            severity: a.severity,
            type: a.attackType,
            timestamp: a.timestamp, // Already formatted or raw string
            action: a.status
        }));

        incidents.forEach((incident, index) => {
            const row = document.createElement('tr');
            row.style.opacity = '0';
            row.style.transform = 'translateX(-20px)';

            // Format timestamp slightly differently if needed, or use as is
            const displayTime = new Date(incident.timestamp).toLocaleString();

            row.innerHTML = `
                <td><span class="severity-badge severity-${incident.severity}">${incident.severity}</span></td>
                <td>${incident.type}</td>
                <td>${displayTime}</td>
                <td><span class="action-badge action-${incident.action}">${incident.action.toUpperCase()}</span></td>
            `;

            incidentsBody.appendChild(row);

            // Animate row appearance
            setTimeout(() => {
                row.style.transition = 'all 0.4s ease';
                row.style.opacity = '1';
                row.style.transform = 'translateX(0)';
            }, index * 100);
        });

    } catch (e) {
        console.error("Failed to load incidents", e);
    }
}

// Login functionality
function initLogin() {
    const loginModal = document.getElementById('loginModal');
    const loginIcon = document.getElementById('loginIcon');
    const loginForm = document.getElementById('loginForm');
    const errorMessage = document.getElementById('errorMessage');

    // Check if user is already logged in
    const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
    const mainContent = document.querySelector('.main-content');

    if (!isLoggedIn) {
        // Show login modal on page load if not logged in
        loginModal.classList.add('active');
        // Hide main content
        if (mainContent) {
            mainContent.classList.add('hidden');
        }
    } else {
        // Show main content if already logged in
        if (mainContent) {
            mainContent.classList.remove('hidden');
        }
    }

    // Open login modal when icon is clicked
    if (loginIcon) {
        loginIcon.addEventListener('click', function () {
            loginModal.classList.add('active');
        });
    }

    // Close modal when clicking outside
    loginModal.addEventListener('click', function (e) {
        if (e.target === loginModal) {
            // Don't allow closing if not logged in
            if (!isLoggedIn) {
                return;
            }
            loginModal.classList.remove('active');
        }
    });

    // Handle form submission
    if (loginForm) {
        loginForm.addEventListener('submit', function (e) {
            e.preventDefault();

            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value.trim();

            // Clear previous error
            errorMessage.classList.remove('show');
            errorMessage.textContent = '';

            // Simple verification (in production, use proper authentication)
            if (username && password) {
                // Simulate authentication check
                // For demo purposes, accept any non-empty credentials
                // In production, verify against backend

                // Show loading state
                const submitButton = loginForm.querySelector('.cyberpunk-button');
                const originalText = submitButton.innerHTML;
                submitButton.innerHTML = '<span>VERIFYING...</span>';
                submitButton.disabled = true;

                // Simulate API call delay
                setTimeout(() => {
                    // Set logged in status
                    sessionStorage.setItem('isLoggedIn', 'true');
                    sessionStorage.setItem('username', username);

                    // Hide modal
                    loginModal.classList.remove('active');

                    // Show main content
                    const mainContent = document.querySelector('.main-content');
                    if (mainContent) {
                        mainContent.classList.remove('hidden');
                        // Initialize dashboard components
                        initMetricAnimations();
                        initThreatChart();
                        initLatencyChart();
                        initHeatmap();
                        initIncidentsTable();
                    }

                    // Reset form
                    loginForm.reset();
                    submitButton.innerHTML = originalText;
                    submitButton.disabled = false;

                    // Show success message (optional)
                    console.log('Login successful!');
                }, 1500);
            } else {
                // Show error
                errorMessage.textContent = 'INVALID CREDENTIALS. ACCESS DENIED.';
                errorMessage.classList.add('show');
            }
        });
    }
}

// Initialize all components when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    // Initialize login first
    initLogin();

    // Only initialize dashboard if logged in
    const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
    if (isLoggedIn) {
        initMetricAnimations();
        initThreatChart();
        initLatencyChart();
        initHeatmap();
        initIncidentsTable();

        // Add smooth scroll behavior
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Add hover effects to cards
        document.querySelectorAll('.metric-card, .chart-card').forEach(card => {
            card.addEventListener('mouseenter', function () {
                this.style.transform = 'translateY(-4px)';
            });

            card.addEventListener('mouseleave', function () {
                this.style.transform = 'translateY(0)';
            });
        });
    }
});

// Simulate live data updates (optional)
setInterval(() => {
    // Update live indicator pulse
    const liveDot = document.querySelector('.live-dot');
    if (liveDot) {
        liveDot.style.animation = 'none';
        setTimeout(() => {
            liveDot.style.animation = 'pulse 2s infinite';
        }, 10);
    }
}, 5000);

/**
 * PROJECT AEGIS - Premium Cursor Trail
 */
const initCursorTrail = () => {
    const container = document.getElementById('cursor-trail-container');
    if (!container) return;

    let particles = [];
    const particleCount = 20;

    for (let i = 0; i < particleCount; i++) {
        const p = document.createElement('div');
        p.className = 'cursor-particle';
        p.style.width = '6px';
        p.style.height = '6px';
        p.style.opacity = '0';
        container.appendChild(p);
        particles.push({
            el: p,
            x: 0,
            y: 0,
            targetX: 0,
            targetY: 0,
            alpha: 0
        });
    }

    let mouseX = 0;
    let mouseY = 0;

    window.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    const animate = () => {
        let x = mouseX;
        let y = mouseY;

        particles.forEach((p, index) => {
            const nextP = particles[index + 1] || particles[0];

            p.x += (x - p.x) * 0.35;
            p.y += (y - p.y) * 0.35;

            p.el.style.transform = `translate(${p.x}px, ${p.y}px) scale(${1 - index / particleCount})`;
            p.el.style.opacity = (1 - index / particleCount) * 0.6;

            x = p.x;
            y = p.y;
        });

        requestAnimationFrame(animate);
    };

    animate();
};

document.addEventListener('DOMContentLoaded', initCursorTrail);

