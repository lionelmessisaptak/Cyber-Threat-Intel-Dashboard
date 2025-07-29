document.addEventListener('DOMContentLoaded', function () {
    // ===================== Scan Trends Chart =====================
    const scanCanvas = document.getElementById('scanChart');
    if (scanCanvas) {
        const ctx = scanCanvas.getContext('2d');

        const chartLabels = window.chartLabels || [];
        const chartMalicious = window.chartMalicious || [];
        const chartClean = window.chartClean || [];

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: chartLabels,
                datasets: [
                    {
                        label: 'Malicious',
                        data: chartMalicious,
                        backgroundColor: 'rgba(239, 83, 80, 0.8)'
                    },
                    {
                        label: 'Clean',
                        data: chartClean,
                        backgroundColor: 'rgba(100, 181, 246, 0.8)'
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' },
                        grid: { color: '#2c3e50' }
                    },
                    x: {
                        ticks: { color: '#ffffff' },
                        grid: { color: '#2c3e50' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                }
            }
        });
    }

    // ===================== Abuse Score Gauge =====================
    const abuseCanvas = document.getElementById('abuseGauge');
    if (abuseCanvas) {
        const ctx = abuseCanvas.getContext('2d');
        const abuseScore = parseInt(abuseCanvas.getAttribute('data-score')) || 0;

        const gradient = ctx.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, '#ff8080');
        gradient.addColorStop(0.5, '#ff3333');
        gradient.addColorStop(1, '#990000');

        const gaugeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Score', 'Remaining'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [gradient, '#1b263b'],
                    borderWidth: 0,
                    cutout: '75%'
                }]
            },
            options: {
                animation: {
                    animateRotate: true,
                    duration: 1200
                },
                plugins: {
                    doughnutlabel: {
                        labels: [
                            {
                                text: abuseScore.toString(),
                                font: { size: '30' },
                                color: '#ffffff'
                            },
                            {
                                text: '/100',
                                font: { size: '14' },
                                color: '#cccccc'
                            }
                        ]
                    },
                    legend: { display: false }
                }
            }
        });

        setTimeout(() => {
            gaugeChart.data.datasets[0].data = [abuseScore, 100 - abuseScore];
            gaugeChart.update();
        }, 300);
    }

    // ===================== Log Section Switching =====================
    const buttons = document.querySelectorAll('.log-button');
    const sections = document.querySelectorAll('.log-section');
    const defaultSection = document.getElementById('ip-log-section');

    buttons.forEach(button => {
        button.addEventListener('click', function () {
            const targetId = button.getAttribute('data-target');
            sections.forEach(sec => sec.style.display = 'none');
            const targetSection = document.getElementById(targetId);
            if (targetSection) targetSection.style.display = 'block';
        });
    });

    if (defaultSection) defaultSection.style.display = 'block';

    // ===================== Lookup Grid Layout Adjust =====================
    const grid = document.querySelector(".lookup-grid");
    const gauge = document.querySelector("#abuseGauge");
    if (grid && !gauge) {
        grid.classList.add("single-column");
    }
});
