document.addEventListener('DOMContentLoaded', () => {
    loadPKIStatus();
    setInterval(loadPKIStatus, 10000);
});

async function loadPKIStatus() {
    try {
        const response = await fetch('/api/status');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        displayStatus(data);
        updateLastUpdated();
    } catch (error) {
        displayError('Failed to load PKI status: ' + error.message);
    }
}

function displayStatus(data) {
    const statusContent = document.getElementById('statusContent');
    const isHealthy = data.status === 'Healthy';
    
    statusContent.innerHTML = `
        <div class="status-card ${isHealthy ? 'healthy' : 'unhealthy'}">
            <div class="status-badge">
                ${isHealthy ? '✅' : '⚠️'} ${data.status}
            </div>
            <p class="status-message">${data.message}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📜</div>
                <div class="stat-value">${data.total_certificates}</div>
                <div class="stat-label">Total Certificates</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">🔑</div>
                <div class="stat-value">${data.total_keys}</div>
                <div class="stat-label">Total Keys</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">👤</div>
                <div class="stat-value">${data.tracked_subject_names}</div>
                <div class="stat-label">Tracked Subjects</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">🔗</div>
                <div class="stat-value">${data.pki_chain_in_sync ? '✓' : '✗'}</div>
                <div class="stat-label">Chain Sync Status</div>
            </div>
        </div>

        <div class="validation-section">
            <h3>Chain Validation</h3>
            <div class="validation-grid">
                <div class="validation-item ${data.certificate_chain_valid ? 'valid' : 'invalid'}">
                    <span class="validation-icon">${data.certificate_chain_valid ? '✅' : '❌'}</span>
                    <span>Certificate Chain</span>
                </div>
                <div class="validation-item ${data.private_key_chain_valid ? 'valid' : 'invalid'}">
                    <span class="validation-icon">${data.private_key_chain_valid ? '✅' : '❌'}</span>
                    <span>Private Key Chain</span>
                </div>
            </div>
        </div>
    `;
}

function displayError(message) {
    const statusContent = document.getElementById('statusContent');
    statusContent.innerHTML = `
        <div class="error-card">
            <div class="error-icon">❌</div>
            <div class="error-message">${escapeHtml(message)}</div>
        </div>
    `;
}

function updateLastUpdated() {
    const lastUpdated = document.getElementById('lastUpdated');
    const now = new Date();
    lastUpdated.textContent = `Last updated: ${now.toLocaleTimeString()}`;
}

function refreshStatus() {
    loadPKIStatus();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
