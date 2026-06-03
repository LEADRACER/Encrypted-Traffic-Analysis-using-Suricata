// Pipeline control state
let pipelineActive = false;
let pipelineThreads = [];

class SuricataDashboard {
    constructor() {
        this.events = [];
        this.stats = {
            total: 0,
            alerts: 0,
            dns: 0,
            http: 0,
            tls: 0,
            blocked: 0
        };
        this.protocolCounts = {};
        this.timelineData = [];
        this.lastSuricataPosition = 0;
        this.lastWiresharkPosition = 0;
        this.eveFilePath = '/api/suricata/eve.json';
        this.wiresharkFilePath = '/api/wireshark/realtime.json';
        this.summaryFilePath = '/api/analysis/summary.json';
        
        // Initialize charts
        this.initCharts();
        
        // Start updating
        this.updateStatus('disconnected');
        this.startFileWatchers();
        this.startSummaryWatcher();
        this.startUpdates();
    }
    
    initCharts() {
        // Protocol distribution chart
        const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
        this.protocolChart = new Chart(protocolCtx, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#3498db', '#e74c3c', '#2ecc71', 
                        '#f39c12', '#9b59b6', '#1abc9c'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                    },
                    title: {
                        display: true,
                        text: 'Protocol Distribution'
                    }
                }
            }
        });
        
        // Timeline chart
        const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
        this.timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Events per minute',
                    data: [],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Events Timeline'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    updateStatus(status) {
        const statusEl = document.getElementById('status');
        statusEl.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        statusEl.className = status;
        
        const now = new Date();
        document.getElementById('last-update').textContent = 
            `Last update: ${now.toLocaleTimeString()}`;
    }
    
    async startFileWatchers() {
        // Start watching both files
        this.watchSuricataFile();
        this.watchWiresharkFile();
    }
    
    startSummaryWatcher() {
        // Start watching the summary file
        setInterval(() => this.checkForSummaryUpdates(), 5000);
    }
    
    async watchSuricataFile() {
        try {
            const response = await fetch(this.eveFilePath);
            if (!response.ok) throw new Error('Cannot access eve.json');
            
            // Get initial file size
            const blob = await response.blob();
            this.lastSuricataPosition = blob.size;
            this.updateStatus('connected');
            
            // Start polling for changes
            setInterval(() => this.checkForSuricataUpdates(), 1000);
        } catch (error) {
            console.error('Suricata file watcher error:', error);
            this.updateStatus('disconnected');
            // Try again in 5 seconds
            setTimeout(() => this.watchSuricataFile(), 5000);
        }
    }
    
    async watchWiresharkFile() {
        try {
            const response = await fetch(this.wiresharkFilePath);
            if (!response.ok) {
                // File might not exist yet, that's OK
                console.log('Wireshark log file not yet available');
                setTimeout(() => this.watchWiresharkFile(), 2000);
                return;
            }
            
            // Get initial file size
            const blob = await response.blob();
            this.lastWiresharkPosition = blob.size;
            
            // Start polling for changes
            setInterval(() => this.checkForWiresharkUpdates(), 1000);
        } catch (error) {
            console.error('Wireshark file watcher error:', error);
            // Try again in 2 seconds
            setTimeout(() => this.watchWiresharkFile(), 2000);
        }
    }
    
    async checkForSuricataUpdates() {
        try {
            const response = await fetch(this.eveFilePath);
            if (!response.ok) return;
            
            const blob = await response.blob();
            const currentSize = blob.size;
            
            if (currentSize > this.lastSuricataPosition) {
                // New data available
                const arrayBuffer = await blob.arrayBuffer();
                const text = new TextDecoder().decode(
                    arrayBuffer.slice(this.lastSuricataPosition)
                );
                
                this.processSuricataData(text);
                this.lastSuricataPosition = currentSize;
}
        } catch (error) {
            console.error('Error checking Suricata updates:', error);
        }
    }
     
    async checkForWiresharkUpdates() {
        try {
            const response = await fetch(this.wiresharkFilePath);
            if (!response.ok) return;
            
            const blob = await response.blob();
            const currentSize = blob.size;
            
            if (currentSize > this.lastWiresharkPosition) {
                // New data available
                const arrayBuffer = await blob.arrayBuffer();
                const text = new TextDecoder().decode(
                    arrayBuffer.slice(this.lastWiresharkPosition)
                );
                
                this.processWiresharkData(text);
                this.lastWiresharkPosition = currentSize;
            }
        } catch (error) {
            console.error('Error checking Wireshark updates:', error);
        }
    }
    
    async checkForSummaryUpdates() {
        try {
            const response = await fetch(this.summaryFilePath);
            if (!response.ok) return;
            
            const summary = await response.json();
            this.processSummaryData(summary);
        } catch (error) {
            console.error('Error checking summary updates:', error);
        }
    }
    
    processSummaryData(summary) {
        // Update dashboard statistics from summary
        if (summary.total_tls_connections !== undefined) {
            this.stats.tls = summary.total_tls_connections;
            document.getElementById('tls-sessions').textContent = this.stats.tls;
        }
        
        if (summary.total_flows_analyzed !== undefined) {
            // This is already updated by Suricata events, but we can use it for validation
        }
        
        if (summary.anomalies_detected !== undefined) {
            // Update blocked count from anomalies
            this.stats.blocked = summary.anomalies_detected;
            document.getElementById('blocked-ips').textContent = this.stats.blocked;
        }
        
        if (summary.blocked_ips_count !== undefined) {
            // Alternatively use the direct count
            this.stats.blocked = summary.blocked_ips_count;
            document.getElementById('blocked-ips').textContent = this.stats.blocked;
        }
        
        if (summary.blocked_ips_list && summary.blocked_ips_list.length > 0) {
            // Optionally, we could display the list of blocked IPs somewhere
            console.log(`Blocked IPs: ${summary.blocked_ips_list.join(', ')}`);
        }
        
        // Update last update time
        const now = new Date();
        document.getElementById('last-update').textContent = 
            `Last update: ${now.toLocaleTimeString()}`;
    }
    
    processSuricataData(text) {
        const lines = text.trim().split('\n').filter(line => line.length > 0);
        
        for (const line of lines) {
            try {
                const event = JSON.parse(line);
                this.processEvent(event, 'suricata');
            } catch (e) {
                // Skip invalid JSON lines
                continue;
            }
        }
        
        if (lines.length > 0) {
            this.updateDashboard();
        }
    }
    
    processWiresharkData(text) {
        const lines = text.trim().split('\n').filter(line => 
            line.length > 0 && !line.startsWith('#')
        );
        
        for (const line of lines) {
            try {
                const event = JSON.parse(line);
                this.processEvent(event, 'wireshark');
            } catch (e) {
                // Skip invalid JSON lines
                continue;
            }
        }
        
        if (lines.length > 0) {
            this.updateDashboard();
        }
    }
    
    processEvent(event, source) {
        // Add to events list (keep last 50)
        this.events.unshift({
            ...event,
            _source: source
        });
        if (this.events.length > 50) {
            this.events.pop();
        }
        
        // Update statistics
        this.stats.total++;
        
        if (event.event_type === 'alert') {
            this.stats.alerts++;
        }
        
        if (event.event_type === 'dns') {
            this.stats.dns++;
        }
        
        if (event.event_type === 'http') {
            this.stats.http++;
        }
        
        if (event.event_type === 'tls') {
            this.stats.tls++;
        }
        
        // Count blocked/dropped packets
        if (event.action === 'drop' || event.action === 'blocked') {
            this.stats.blocked++;
        }
        
        // Update protocol distribution
        const proto = event.proto || event['_layers']?.tcp ? 'TCP' : 
                     event['_layers']?.udp ? 'UDP' : 'OTHER';
        this.protocolCounts[proto] = (this.protocolCounts[proto] || 0) + 1;
        
        // Update timeline data (events per minute)
        const now = new Date();
        const timestamp = event.timestamp ? new Date(event.timestamp) : now;
        this.updateTimeline(timestamp);
    }
    
    updateTimeline(timestamp) {
        // Group events by minute for the last 30 minutes
        const now = new Date();
        const thirtyMinutesAgo = new Date(now.getTime() - 30 * 60 * 1000);
        
        // Filter recent events
        const recentEvents = this.events.filter(e => {
            const eventTime = e.timestamp ? new Date(e.timestamp) : now;
            return eventTime >= thirtyMinutesAgo;
        });
        
        // Group by minute
        const minuteGroups = {};
        recentEvents.forEach(event => {
            const eventTime = event.timestamp ? new Date(event.timestamp) : now;
            const minuteKey = eventTime.toISOString().slice(0, 16); // YYYY-MM-DDTHH:mm
            minuteGroups[minuteKey] = (minuteGroups[minuteKey] || 0) + 1;
        });
        
        // Convert to sorted arrays
        const sortedMinutes = Object.keys(minuteGroups).sort();
        this.timelineData = {
            labels: sortedMinutes.map(min => {
                const date = new Date(min + ':00');
                return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            }),
            data: sortedMinutes.map(min => minuteGroups[min])
        };
        
        // Limit to last 20 data points
        if (this.timelineData.labels.length > 20) {
            this.timelineData.labels = this.timelineData.labels.slice(-20);
            this.timelineData.data = this.timelineData.data.slice(-20);
        }
    }
    
    updateDashboard() {
        // Update statistics
        document.getElementById('total-events').textContent = this.stats.total;
        document.getElementById('alerts').textContent = this.stats.alerts;
        document.getElementById('dns-queries').textContent = this.stats.dns;
        document.getElementById('http-flows').textContent = this.stats.http;
        document.getElementById('tls-sessions').textContent = this.stats.tls;
        document.getElementById('blocked-ips').textContent = this.stats.blocked;
        
        // Update events list
        this.updateEventsList();
        
        // Update charts
        this.updateCharts();
    }
    
    updateEventsList() {
        const container = document.getElementById('events-container');
        
        if (this.events.length === 0) {
            container.innerHTML = '<div class="empty">No events yet</div>';
            return;
        }
        
        container.innerHTML = this.events.slice(0, 20).map(event => {
            const time = new Date(event.timestamp || Date.now())
                .toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
            
            let type = event.event_type || 'unknown';
            let details = '';
            let actionClass = '';
            let sourceIcon = event._source === 'suricata' ? '🛡️' : '📡';
            
            if (event.event_type === 'dns') {
                details = `${event.dns_qry_name || event.dns?.rrname || 'DNS Query'} ` +
                         `(${event.dns_qry_type || event.dns?.type || 'query'})`;
            } else if (event.event_type === 'alert') {
                details = event.alert?.signature || event.alert || 'Security Alert';
                actionClass = 'alert';
            } else if (event.event_type === 'http') {
                details = `${event.http_hostname || event.http?.hostname || ''} ` +
                         `${event.http_url || event.http?.url || ''}`.trim();
                actionClass = event.alert ? 'alert' : '';
            } else if (event.event_type === 'tls') {
                details = `TLS ${event.tls_version || event.tls?.version || ''} ` +
                         `(JA3: ${event.ja3_hash?.substring(0,8) ?? 'unknown'})`;
            } else {
                details = `${event.src_ip || ''}:${event.src_port || ''} → ` +
                         `${event.dest_ip || ''}:${event.dest_port || ''}`;
            }
            
            if (event.action === 'drop' || event.action === 'blocked') {
                actionClass = 'drop';
            }
            
            return `
                <div class="event-item">
                    <div class="event-timestamp">${time}</div>
                    <div class="event-type">${sourceIcon} ${type}</div>
                    <div class="event-details">${details}</div>
                    <div class="event-action ${actionClass}">${event.action || ''}</div>
                </div>
            `;
        }).join('');
    }
    
    updateCharts() {
        // Update protocol chart
        const protocolLabels = Object.keys(this.protocolCounts);
        const protocolData = protocolLabels.map(key => this.protocolCounts[key]);
        
        this.protocolChart.data.labels = protocolLabels;
        this.protocolChart.data.datasets[0].data = protocolData;
        this.protocolChart.update('none');
        
        // Update timeline chart
        if (this.timelineData.labels.length > 0) {
            this.timelineChart.data.labels = this.timelineData.labels;
            this.timelineChart.data.datasets[0].data = this.timelineData.data;
            this.timelineChart.update('none');
        }
    }
    
    startUpdates() {
        // Update dashboard every second even if no new data
        setInterval(() => {
            const suricataConnected = this.lastSuricataPosition > 0;
            const wiresharkAvailable = this.lastWiresharkPosition >= 0; // 0 means file exists
            this.updateStatus(suricataConnected || wiresharkAvailable ? 'connected' : 'disconnected');
        }, 1000);
    }
}

// Pipeline control functions
function startPipeline() {
    if (pipelineActive) return;
    
    const interface = document.getElementById('interface').value;
    const duration = parseInt(document.getElementById('duration').value) || 60;
    const realtime = document.getElementById('realtime').checked;
    const ips = document.getElementById('ips').checked;
    const block = document.getElementById('block').checked;
    const analyze = document.getElementById('analyze').checked;
    const capture = document.getElementById('capture').checked;
    const all = document.getElementById('all').checked;
    
    // Show loading state
    document.getElementById('start-btn').disabled = true;
    document.getElementById('stop-btn').disabled = false;
    
    // Start pipeline via fetch to dashboard server API
    fetch('/api/start-pipeline', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            interface: interface,
            duration: duration,
            realtime: realtime,
            ips: ips,
            block: block,
            analyze: analyze,
            capture: capture,
            all: all
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            pipelineActive = true;
            console.log('Pipeline started successfully');
        } else {
            alert('Failed to start pipeline: ' + data.error);
            document.getElementById('start-btn').disabled = false;
            document.getElementById('stop-btn').disabled = true;
        }
    })
    .catch(error => {
        console.error('Error starting pipeline:', error);
        alert('Failed to start pipeline: ' + error.message);
        document.getElementById('start-btn').disabled = false;
        document.getElementById('stop-btn').disabled = true;
    });
}

function stopPipeline() {
    if (!pipelineActive) return;
    
    // Show loading state
    document.getElementById('stop-btn').disabled = true;
    
    // Stop pipeline via fetch to dashboard server API
    fetch('/api/stop-pipeline', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            pipelineActive = false;
            document.getElementById('start-btn').disabled = false;
            document.getElementById('stop-btn').disabled = true;
            console.log('Pipeline stopped successfully');
        } else {
            alert('Failed to stop pipeline: ' + data.error);
            document.getElementById('stop-btn').disabled = false;
        }
    })
    .catch(error => {
        console.error('Error stopping pipeline:', error);
        alert('Failed to stop pipeline: ' + error.message);
        document.getElementById('stop-btn').disabled = false;
    });
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SuricataDashboard();
    
    // Add event listeners to pipeline controls
    document.getElementById('start-btn').addEventListener('click', startPipeline);
    document.getElementById('stop-btn').addEventListener('click', stopPipeline);
});