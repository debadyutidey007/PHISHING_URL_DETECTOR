// Utility Functions

// Format a JSON object with syntax highlighting
function formatJson(obj, pretty = true) {
    const jsonString = pretty ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
    
    // Basic JSON syntax highlighting
    return jsonString
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/(""|".*?[^\\]")/g, function(match) {
            // String values (in quotes)
            return '<span class="json-string">' + match + '</span>';
        })
        .replace(/\b(true|false)\b/g, '<span class="json-boolean">$1</span>')
        .replace(/\b(null)\b/g, '<span class="json-null">$1</span>')
        .replace(/\b(-?\d+\.?\d*(?:e[+-]?\d+)?)\b/gi, '<span class="json-number">$1</span>')
        .replace(/(".*?")\s*:/g, '<span class="json-key">$1</span>:');
}

// Copy text to clipboard
function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    
    textarea.select();
    document.execCommand('copy');
    
    document.body.removeChild(textarea);
}

// Show copy success notification
function showCopySuccess() {
    const container = document.querySelector('.feature-data-container');
    
    // Remove existing notification
    const existingNotification = document.querySelector('.copy-success');
    if (existingNotification) {
        container.removeChild(existingNotification);
    }
    
    // Create new notification
    const notification = document.createElement('div');
    notification.className = 'copy-success';
    notification.textContent = 'Copied to clipboard!';
    container.appendChild(notification);
    
    // Show notification
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    // Hide notification after 2 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            container.removeChild(notification);
        }, 300);
    }, 2000);
}

document.addEventListener('DOMContentLoaded', function() {
    // References to main DOM elements
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultSection = document.getElementById('result-section');
    const loadingSpinner = document.getElementById('loading-spinner');
    const errorAlert = document.getElementById('error-alert');
    const resultContent = document.getElementById('result-content');
    const resultBadge = document.getElementById('result-badge');
    const confidence = document.getElementById('confidence');
    const featureTable = document.getElementById('feature-table');
    const featureChart = document.getElementById('feature-chart');
    const riskGauge = document.getElementById('risk-gauge');
    const scanModeBtn = document.getElementById('scan-mode-btn');
    const batchAnalysisSection = document.getElementById('batch-analysis-section');
    const batchAnalyzeBtn = document.getElementById('batch-analyze-btn');
    const batchUrls = document.getElementById('batch-urls');
    const batchResultsSection = document.getElementById('batch-results-section');
    const batchResultsTable = document.getElementById('batch-results-table');
    const analyzedUrlHeading = document.getElementById('analyzed-url-heading');
    const resultIcon = document.getElementById('result-icon');
    const domainName = document.getElementById('domain-name');
    const urlStructureRisk = document.getElementById('url-structure-risk');
    const urlStructurePercent = document.getElementById('url-structure-percent');
    const domainRisk = document.getElementById('domain-risk');
    const domainRiskPercent = document.getElementById('domain-risk-percent');
    const contentRisk = document.getElementById('content-risk');
    const contentRiskPercent = document.getElementById('content-risk-percent');
    const rawFeatureData = document.getElementById('raw-feature-data');
    const structureAnalysis = document.getElementById('structure-analysis');
    const securityInsights = document.getElementById('security-insights');
    const historyChart = document.getElementById('history-chart');
    const threatDistributionChart = document.getElementById('threat-distribution-chart');
    const totalAnalyzed = document.getElementById('total-analyzed');
    const phishingDetected = document.getElementById('phishing-detected');
    const avgConfidence = document.getElementById('avg-confidence');
    const detectionRate = document.getElementById('detection-rate');
    
    // Chart instances
    let featureImportanceChart = null;
    let riskGaugeChart = null;
    let historyChartInstance = null;
    let threatDistributionChartInstance = null;
    
    // Settings elements
    const sensitivitySlider = document.getElementById('sensitivity-slider');
    const enableAdvancedFeatures = document.getElementById('enable-advanced-features');
    const chartTypeRadios = document.querySelectorAll('input[name="chart-type"]');
    const featureCount = document.getElementById('feature-count');
    
    // Local storage for analytics data
    const analysisHistory = JSON.parse(localStorage.getItem('analysisHistory')) || [];
    let totalAnalyzedCount = parseInt(localStorage.getItem('totalAnalyzedCount')) || 0;
    let phishingDetectedCount = parseInt(localStorage.getItem('phishingDetectedCount')) || 0;
    let confidenceSum = parseFloat(localStorage.getItem('confidenceSum')) || 0;
    
    // Initialize analytics
    updateAnalytics();
    initCharts();
    
    // Event listeners
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        analyzeUrl();
    });
    
    scanModeBtn.addEventListener('click', function() {
        batchAnalysisSection.classList.toggle('d-none');
    });
    
    batchAnalyzeBtn.addEventListener('click', function() {
        analyzeBatchUrls();
    });
    
    // Listen for chart type changes
    chartTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (featureImportanceChart) {
                updateFeatureChart(lastAnalyzedFeatures);
            }
        });
    });
    
    // Listen for feature count changes
    featureCount.addEventListener('change', function() {
        if (featureImportanceChart && lastAnalyzedFeatures) {
            updateFeatureChart(lastAnalyzedFeatures);
        }
    });
    
    // Store last analyzed features for chart updates
    let lastAnalyzedFeatures = null;
    
    // Function to initialize charts
    function initCharts() {
        // Initialize history chart
        const historyData = getHistoryChartData();
        createHistoryChart(historyData);
        
        // Initialize threat distribution chart
        const threatData = getThreatDistributionData();
        createThreatDistributionChart(threatData);
    }
    
    // Function to analyze URL
    function analyzeUrl() {
        const url = urlInput.value.trim();
        
        if (!url) {
            showError('Please enter a URL to analyze');
            return;
        }
        
        // Show loading spinner
        loadingSpinner.classList.remove('d-none');
        resultSection.classList.add('d-none');
        errorAlert.classList.add('d-none');
        analyzeBtn.disabled = true;
        
        // Create form data
        const formData = new FormData();
        formData.append('url', url);
        
        // Get sensitivity setting
        if (sensitivitySlider) {
            formData.append('sensitivity', sensitivitySlider.value);
        }
        
        // Get advanced features setting
        if (enableAdvancedFeatures) {
            formData.append('advanced_features', enableAdvancedFeatures.checked ? '1' : '0');
        }
        
        // Send POST request to analyze endpoint
        fetch('/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            // Hide loading spinner
            loadingSpinner.classList.add('d-none');
            analyzeBtn.disabled = false;
            
            if (data.error) {
                showError(data.error);
                return;
            }
            
            // Display results
            displayResults(data);
            
            // Update analytics
            updateAnalyticsWithNewResult(data);
        })
        .catch(error => {
            // Hide loading spinner
            loadingSpinner.classList.add('d-none');
            analyzeBtn.disabled = false;
            
            // Show error message
            showError('An error occurred while analyzing the URL: ' + error.message);
        });
    }
    
    // Function to analyze batch URLs
    function analyzeBatchUrls() {
        const urls = batchUrls.value.trim().split('\n').filter(url => url.trim().length > 0);
        
        if (urls.length === 0) {
            showError('Please enter at least one URL to analyze');
            return;
        }
        
        // Prepare batch results section
        batchResultsTable.querySelector('tbody').innerHTML = '';
        batchResultsSection.classList.remove('d-none');
        
        // Process each URL
        let completedCount = 0;
        
        urls.forEach((url, index) => {
            // Add a row for this URL
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${url}</td>
                <td><span class="badge bg-secondary">Pending</span></td>
                <td>--</td>
                <td>--</td>
                <td>
                    <button class="btn btn-sm btn-primary view-details-btn" disabled>
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            batchResultsTable.querySelector('tbody').appendChild(row);
            
            // Create a delay to avoid overwhelming the server
            setTimeout(() => {
                analyzeUrlForBatch(url, index, row, () => {
                    completedCount++;
                    if (completedCount === urls.length) {
                        // All URLs have been analyzed
                        showNotification('Batch analysis complete!', 'success');
                    }
                });
            }, index * 1000); // Stagger requests by 1 second
        });
    }
    
    // Analyze a single URL for batch processing
    function analyzeUrlForBatch(url, index, row, callback) {
        // Update row status
        const statusCell = row.cells[1].querySelector('span');
        statusCell.textContent = 'Analyzing...';
        statusCell.classList.remove('bg-secondary');
        statusCell.classList.add('bg-info');
        
        // Create form data
        const formData = new FormData();
        formData.append('url', url);
        
        // Get sensitivity setting
        if (sensitivitySlider) {
            formData.append('sensitivity', sensitivitySlider.value);
        }
        
        // Send POST request to analyze endpoint
        fetch('/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                // Update row with error
                statusCell.textContent = 'Error';
                statusCell.classList.remove('bg-info');
                statusCell.classList.add('bg-warning');
                row.cells[2].textContent = 'N/A';
                row.cells[3].textContent = 'N/A';
            } else {
                // Update row with results
                const isPhishing = data.is_phishing;
                const confidencePercentage = (data.confidence * 100).toFixed(2);
                const riskScore = calculateRiskScore(data);
                
                statusCell.textContent = isPhishing ? 'Phishing' : 'Safe';
                statusCell.classList.remove('bg-info');
                statusCell.classList.add(isPhishing ? 'bg-danger' : 'bg-success');
                
                row.cells[2].textContent = `${confidencePercentage}%`;
                row.cells[3].textContent = `${riskScore}%`;
                
                // Enable view details button
                const viewBtn = row.cells[4].querySelector('button');
                viewBtn.disabled = false;
                viewBtn.addEventListener('click', () => {
                    // Simulate clicking on main URL input and analyze
                    urlInput.value = url;
                    analyzeUrl();
                    
                    // Scroll to results
                    resultSection.scrollIntoView({ behavior: 'smooth' });
                });
                
                // Update analytics
                updateAnalyticsWithNewResult(data);
            }
            
            // Call the completion callback
            callback();
        })
        .catch(error => {
            // Update row with error
            statusCell.textContent = 'Failed';
            statusCell.classList.remove('bg-info');
            statusCell.classList.add('bg-danger');
            row.cells[2].textContent = 'N/A';
            row.cells[3].textContent = 'N/A';
            
            // Call the completion callback
            callback();
        });
    }
    
    // Function to display error message
    function showError(message) {
        errorAlert.textContent = message;
        errorAlert.classList.remove('d-none');
        resultSection.classList.add('d-none');
    }
    
    // Function to display a notification
    function showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.top = '20px';
        notification.style.right = '20px';
        notification.style.zIndex = '9999';
        notification.style.maxWidth = '300px';
        
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add to document
        document.body.appendChild(notification);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 150);
        }, 5000);
    }
    
    // Function to display analysis results
    function displayResults(data) {
        // Show result section
        resultSection.classList.remove('d-none');
        
        // Update URL heading
        if (analyzedUrlHeading) {
            analyzedUrlHeading.textContent = data.url;
        }
        
        // Update domain information
        if (domainName) {
            const domain = extractDomain(data.url);
            domainName.textContent = domain;
        }
        
        // Update result badge and icon
        if (data.is_phishing) {
            resultBadge.textContent = 'Phishing URL Detected';
            resultBadge.classList.remove('bg-success');
            resultBadge.classList.add('bg-danger');
            
            if (resultIcon) {
                resultIcon.className = 'me-3 fs-1 text-danger';
                resultIcon.innerHTML = '<i class="fas fa-shield-exclamation"></i>';
            }
        } else {
            resultBadge.textContent = 'Safe URL';
            resultBadge.classList.remove('bg-danger');
            resultBadge.classList.add('bg-success');
            
            if (resultIcon) {
                resultIcon.className = 'me-3 fs-1 text-success';
                resultIcon.innerHTML = '<i class="fas fa-shield-check"></i>';
            }
        }
        
        // Update confidence
        const confidencePercentage = (data.confidence * 100).toFixed(2);
        confidence.textContent = `Confidence: ${confidencePercentage}%`;
        
        // Update threat assessment
        updateThreatAssessment(data);
        
        // Update feature table
        updateFeatureTable(data.top_features);
        
        // Store for chart updates
        lastAnalyzedFeatures = data.top_features;
        
        // Update feature chart based on selected type
        updateFeatureChart(data.top_features);
        
        // Update risk gauge
        updateRiskGauge(data);
        
        // Update advanced analysis tabs
        updateAdvancedAnalysisTabs(data);
    }
    
    // Function to extract domain from URL
    function extractDomain(url) {
        try {
            const urlObj = new URL(url.startsWith('http') ? url : 'http://' + url);
            return urlObj.hostname;
        } catch (e) {
            return url;
        }
    }
    
    // Function to update threat assessment visualizations
    function updateThreatAssessment(data) {
        // Calculate risk scores for different components
        const features = data.features;
        
        // URL Structure Risk (based on URL length, special chars, etc)
        const urlRiskScore = calculateUrlStructureRisk(features);
        if (urlStructureRisk && urlStructurePercent) {
            urlStructureRisk.style.width = `${urlRiskScore}%`;
            urlStructureRisk.className = `progress-bar ${getRiskColorClass(urlRiskScore)}`;
            urlStructurePercent.textContent = `${urlRiskScore}%`;
        }
        
        // Domain Risk (based on domain properties)
        const domainRiskScore = calculateDomainRisk(features);
        if (domainRisk && domainRiskPercent) {
            domainRisk.style.width = `${domainRiskScore}%`;
            domainRisk.className = `progress-bar ${getRiskColorClass(domainRiskScore)}`;
            domainRiskPercent.textContent = `${domainRiskScore}%`;
        }
        
        // Content Risk (placeholder, as we don't actually analyze content)
        const contentRiskScore = 10; // Default low risk
        if (contentRisk && contentRiskPercent) {
            contentRisk.style.width = `${contentRiskScore}%`;
            contentRisk.className = `progress-bar ${getRiskColorClass(contentRiskScore)}`;
            contentRiskPercent.textContent = `${contentRiskScore}%`;
        }
    }
    
    // Helper function to get color class based on risk score
    function getRiskColorClass(score) {
        if (score < 30) return 'bg-success';
        if (score < 70) return 'bg-warning';
        return 'bg-danger';
    }
    
    // Calculate URL structure risk
    function calculateUrlStructureRisk(features) {
        let score = 0;
        
        // URL length (longer URLs are riskier)
        if (features.url_length > 100) score += 20;
        else if (features.url_length > 75) score += 10;
        else if (features.url_length > 50) score += 5;
        
        // Special characters
        score += Math.min(20, features.num_special_chars);
        
        // URL depth (deeper paths are riskier)
        if (features.url_depth > 5) score += 15;
        else if (features.url_depth > 3) score += 10;
        else if (features.url_depth > 1) score += 5;
        
        // Suspicious terms
        score += features.suspicious_terms_count * 10;
        
        // URL encoding
        score += features.url_encoded_chars * 5;
        
        // Cap at 100%
        return Math.min(100, score);
    }
    
    // Calculate domain risk
    function calculateDomainRisk(features) {
        let score = 0;
        
        // Suspicious TLD
        if (features.has_suspicious_tld) score += 40;
        
        // IP address in URL
        if (features.has_ip_address) score += 30;
        
        // @ symbol in URL
        if (features.has_at_symbol) score += 30;
        
        // Multiple subdomains
        if (features.has_multiple_subdomains) score += 20;
        
        // Domain includes dash
        if (features.has_dash_in_domain) score += 15;
        
        // Cap at 100%
        return Math.min(100, score);
    }
    
    // Calculate overall risk score
    function calculateRiskScore(data) {
        const features = data.features;
        const isPhishing = data.is_phishing;
        const confidence = data.confidence;
        
        // Base score on prediction and confidence
        let score = isPhishing ? 70 : 30;
        score = isPhishing ? score + (confidence * 30) : score - (confidence * 20);
        
        // Adjust based on specific high-risk features
        if (features.has_ip_address) score += 10;
        if (features.has_at_symbol) score += 10;
        if (features.has_suspicious_tld) score += 10;
        if (features.suspicious_terms_count > 2) score += 10;
        
        // Cap score at 0-100
        return Math.max(0, Math.min(100, Math.round(score)));
    }
    
    // Function to update the feature table
    function updateFeatureTable(features) {
        // Clear existing table content
        const tbody = featureTable.querySelector('tbody');
        tbody.innerHTML = '';
        
        // Get selected feature count
        const selectedCount = featureCount ? featureCount.value : '5';
        const displayFeatures = selectedCount === 'all' ? features : features.slice(0, parseInt(selectedCount));
        
        // Add rows for each feature
        displayFeatures.forEach(feature => {
            const row = document.createElement('tr');
            
            const nameCell = document.createElement('td');
            nameCell.textContent = formatFeatureName(feature.feature);
            
            const valueCell = document.createElement('td');
            valueCell.textContent = formatFeatureValue(feature.value);
            
            const importanceCell = document.createElement('td');
            const importancePercentage = (feature.importance * 100).toFixed(2);
            importanceCell.textContent = `${importancePercentage}%`;
            
            // Add impact cell with indicator
            const impactCell = document.createElement('td');
            const impact = getFeatureImpact(feature.feature, feature.value);
            const impactHtml = `
                <div class="d-flex align-items-center">
                    <span class="impact-indicator ${impact.class}"></span>
                    <span>${impact.label}</span>
                </div>
            `;
            impactCell.innerHTML = impactHtml;
            
            row.appendChild(nameCell);
            row.appendChild(valueCell);
            row.appendChild(importanceCell);
            row.appendChild(impactCell);
            
            tbody.appendChild(row);
        });
    }
    
    // Format feature value based on type
    function formatFeatureValue(value) {
        if (typeof value === 'boolean') {
            return value ? 'Yes' : 'No';
        }
        if (value === 0 || value === 1) {
            return value === 1 ? 'Yes' : 'No';
        }
        return value;
    }
    
    // Get impact class and label for a feature
    function getFeatureImpact(feature, value) {
        // Define high impact features
        const highImpactFeatures = {
            'has_ip_address': 1,
            'has_at_symbol': 1,
            'has_suspicious_tld': 1,
            'has_multiple_subdomains': 1,
            'suspicious_terms_count': 2 // Threshold
        };
        
        // Define medium impact features
        const mediumImpactFeatures = {
            'url_length': 75, // Threshold
            'has_dash_in_domain': 1,
            'url_depth': 4, // Threshold
            'has_double_slash': 1,
            'url_encoded_chars': 2 // Threshold
        };
        
        // Check for high impact
        if (feature in highImpactFeatures) {
            if (typeof value === 'boolean') {
                return value ? { class: 'impact-high', label: 'High' } : { class: 'impact-low', label: 'Low' };
            }
            if (value === 1 || value === 0) {
                return value === 1 ? { class: 'impact-high', label: 'High' } : { class: 'impact-low', label: 'Low' };
            }
            if (value >= highImpactFeatures[feature]) {
                return { class: 'impact-high', label: 'High' };
            }
        }
        
        // Check for medium impact
        if (feature in mediumImpactFeatures) {
            if (typeof value === 'boolean') {
                return value ? { class: 'impact-medium', label: 'Medium' } : { class: 'impact-low', label: 'Low' };
            }
            if (value === 1 || value === 0) {
                return value === 1 ? { class: 'impact-medium', label: 'Medium' } : { class: 'impact-low', label: 'Low' };
            }
            if (value >= mediumImpactFeatures[feature]) {
                return { class: 'impact-medium', label: 'Medium' };
            }
        }
        
        // Default to low impact
        return { class: 'impact-low', label: 'Low' };
    }

    // Function to format feature names for display
    function formatFeatureName(name) {
        return name
            .replace(/_/g, ' ')
            .replace(/\b\w/g, l => l.toUpperCase());
    }

    // Function to update the feature importance chart
    function updateFeatureChart(features) {
        // Destroy previous chart instance if it exists
        if (featureImportanceChart) {
            featureImportanceChart.destroy();
        }
        
        if (!features || features.length === 0) {
            return;
        }
        
        // Get selected chart type and feature count
        const chartType = getSelectedChartType();
        const selectedCount = featureCount ? featureCount.value : '5';
        const displayFeatures = selectedCount === 'all' ? features : features.slice(0, parseInt(selectedCount));
        
        // Prepare data for the chart
        const labels = displayFeatures.map(feature => formatFeatureName(feature.feature));
        const importanceValues = displayFeatures.map(feature => feature.importance);
        
        // Create chart configuration based on type
        const chartConfig = {
            type: chartType,
            data: {
                labels: labels,
                datasets: [{
                    label: 'Feature Importance',
                    data: importanceValues,
                    backgroundColor: getChartColors(chartType, displayFeatures.length),
                    borderColor: chartType === 'radar' ? 'rgba(13, 110, 253, 0.8)' : getChartColors(chartType, displayFeatures.length),
                    borderWidth: 1,
                    fill: chartType === 'radar' ? true : false
                }]
            },
            options: getChartOptions(chartType)
        };
        
        // Create a new chart
        const ctx = featureChart.getContext('2d');
        featureImportanceChart = new Chart(ctx, chartConfig);
    }
    
    // Get selected chart type from radio buttons
    function getSelectedChartType() {
        if (document.getElementById('chart-radar').checked) {
            return 'radar';
        }
        if (document.getElementById('chart-pie').checked) {
            return 'pie';
        }
        return 'bar'; // Default
    }
    
    // Get chart colors based on type and count
    function getChartColors(type, count) {
        if (type === 'pie') {
            // Generate array of colors for pie chart
            return Array(count).fill().map((_, i) => 
                `hsl(${210 + i * (360 / count)}, 70%, 60%)`
            );
        }
        
        if (type === 'radar') {
            return 'rgba(13, 110, 253, 0.3)';
        }
        
        // Default for bar chart
        return 'rgba(13, 110, 253, 0.7)';
    }
    
    // Get chart options based on type
    function getChartOptions(type) {
        const baseOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: type === 'pie',
                    position: 'top'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const value = context.raw;
                            return `Importance: ${(value * 100).toFixed(2)}%`;
                        }
                    }
                }
            }
        };
        
        if (type === 'bar') {
            return {
                ...baseOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Importance'
                        },
                        ticks: {
                            callback: function(value) {
                                return (value * 100).toFixed(0) + '%';
                            }
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Features'
                        }
                    }
                }
            };
        }
        
        if (type === 'radar') {
            return {
                ...baseOptions,
                scales: {
                    r: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return (value * 100).toFixed(0) + '%';
                            },
                            stepSize: 0.2
                        },
                        pointLabels: {
                            font: {
                                size: 10
                            }
                        }
                    }
                }
            };
        }
        
        // Default pie chart options
        return baseOptions;
    }
    
    // Function to update the risk gauge
    function updateRiskGauge(data) {
        if (!riskGauge) return;
        
        // Calculate risk score
        const riskScore = calculateRiskScore(data);
        
        // Destroy previous chart instance
        if (riskGaugeChart) {
            riskGaugeChart.destroy();
        }
        
        // Create the gauge chart
        const ctx = riskGauge.getContext('2d');
        riskGaugeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Risk', 'Safe'],
                datasets: [{
                    data: [riskScore, 100 - riskScore],
                    backgroundColor: [
                        getGaugeColor(riskScore),
                        'rgba(200, 200, 200, 0.1)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                circumference: 180,
                rotation: -90,
                cutout: '75%',
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: false
                    }
                }
            },
            plugins: [{
                id: 'riskText',
                afterDraw: function(chart) {
                    const width = chart.width;
                    const height = chart.height;
                    const ctx = chart.ctx;
                    
                    ctx.restore();
                    ctx.font = 'bold 20px Arial';
                    ctx.textBaseline = 'middle';
                    ctx.textAlign = 'center';
                    
                    // Add risk score text
                    ctx.fillStyle = getGaugeColor(riskScore);
                    ctx.fillText(riskScore + '%', width / 2, height - 30);
                    
                    // Add risk label text
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#888';
                    ctx.fillText('Risk Score', width / 2, height - 10);
                    
                    ctx.save();
                }
            }]
        });
    }
    
    // Get gauge color based on risk score
    function getGaugeColor(score) {
        if (score < 30) return '#20c997'; // Low risk - green
        if (score < 50) return '#0dcaf0'; // Low-medium risk - cyan
        if (score < 70) return '#ffc107'; // Medium risk - yellow
        if (score < 85) return '#fd7e14'; // Medium-high risk - orange
        return '#dc3545'; // High risk - red
    }
    
    // Function to update advanced analysis tabs
    function updateAdvancedAnalysisTabs(data) {
        // Update raw feature data
        if (rawFeatureData) {
            // Store the raw data for format switching
            const rawData = data.features;
            
            // Format and syntax highlight the JSON
            const formattedJson = formatJson(rawData, true); // Start with pretty format
            rawFeatureData.innerHTML = formattedJson;
            
            // Setup copy button
            const copyBtn = document.getElementById('copy-json-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    copyToClipboard(JSON.stringify(rawData, null, 2));
                    showCopySuccess();
                });
            }
            
            // Setup format switcher
            const formatSelect = document.getElementById('json-format-select');
            if (formatSelect) {
                formatSelect.addEventListener('change', () => {
                    const isPretty = formatSelect.value === 'pretty';
                    rawFeatureData.innerHTML = formatJson(rawData, isPretty);
                });
            }
        }
        
        // Update domain info if available
        const domainInfoEl = document.getElementById('domain-info');
        if (domainInfoEl && data.domain_info) {
            const info = data.domain_info;
            let html = '';
            
            Object.keys(info).forEach(key => {
                if (key !== 'error') {
                    const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                    html += `
                        <div class="domain-info-item">
                            <span class="info-label">${formattedKey}</span>
                            <span class="info-value">`;
                            
                    // Special formatting for certain values
                    if (key === 'ssl_valid') {
                        html += info[key] ? 
                            '<span class="badge bg-success">Secure</span>' : 
                            '<span class="badge bg-warning">Not Secure</span>';
                    } else {
                        html += info[key];
                    }
                    
                    html += `</span>
                        </div>`;
                }
            });
            
            domainInfoEl.innerHTML = html;
        }
        
        // Update structure analysis
        if (structureAnalysis) {
            const url = data.url;
            let urlObj;
            
            try {
                urlObj = new URL(url.startsWith('http') ? url : 'http://' + url);
            } catch (e) {
                urlObj = null;
            }
            
            if (urlObj) {
                structureAnalysis.innerHTML = `
                    <div class="mb-3">
                        <h6>URL Components:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <tr>
                                    <th>Protocol</th>
                                    <td>${urlObj.protocol.replace(':', '')}</td>
                                </tr>
                                <tr>
                                    <th>Domain</th>
                                    <td>${urlObj.hostname}</td>
                                </tr>
                                <tr>
                                    <th>Path</th>
                                    <td>${urlObj.pathname || '/'}</td>
                                </tr>
                                <tr>
                                    <th>Query</th>
                                    <td>${urlObj.search || 'None'}</td>
                                </tr>
                                <tr>
                                    <th>Fragment</th>
                                    <td>${urlObj.hash || 'None'}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    <div>
                        <h6>Structure Characteristics:</h6>
                        <ul class="list-unstyled mb-0">
                            <li><i class="fas fa-ruler me-2 text-primary"></i> URL Length: ${data.features.url_length} characters</li>
                            <li><i class="fas fa-folder me-2 text-primary"></i> Path Depth: ${data.features.url_depth} levels</li>
                            <li><i class="fas fa-hashtag me-2 text-primary"></i> Special Characters: ${data.features.num_special_chars}</li>
                            <li><i class="fas fa-code me-2 text-primary"></i> URL Encoding: ${data.features.url_encoded_chars} characters</li>
                        </ul>
                    </div>
                `;
            } else {
                structureAnalysis.innerHTML = '<div class="alert alert-warning">Unable to parse URL structure</div>';
            }
        }
        
        // Update security insights
        if (securityInsights) {
            const features = data.features;
            const isPhishing = data.is_phishing;
            
            let insights = '';
            
            if (isPhishing) {
                insights += `
                    <div class="security-warning mb-3">
                        <h6><i class="fas fa-exclamation-triangle me-2"></i> High Risk Detected</h6>
                        <p class="mb-0">This URL has been classified as a potential phishing attempt with ${(data.confidence * 100).toFixed(2)}% confidence.</p>
                    </div>
                `;
                
                // Add specific warnings
                if (features.has_ip_address) {
                    insights += `
                        <div class="security-warning mb-2">
                            <strong>IP Address Detected:</strong> The URL contains an IP address instead of a domain name, which is often associated with phishing attempts.
                        </div>
                    `;
                }
                
                if (features.has_at_symbol) {
                    insights += `
                        <div class="security-warning mb-2">
                            <strong>@ Symbol Detected:</strong> The URL contains an @ symbol, which can be used to obscure the actual destination.
                        </div>
                    `;
                }
                
                if (features.has_suspicious_tld) {
                    insights += `
                        <div class="security-warning mb-2">
                            <strong>Suspicious TLD:</strong> The domain uses a top-level domain (TLD) that is commonly associated with free or abusive registrations.
                        </div>
                    `;
                }
                
                if (features.suspicious_terms_count > 0) {
                    insights += `
                        <div class="security-warning mb-2">
                            <strong>Suspicious Terms:</strong> The URL contains terms commonly associated with phishing (${features.suspicious_terms_count} found).
                        </div>
                    `;
                }
            } else {
                insights += `
                    <div class="security-tip mb-3">
                        <h6><i class="fas fa-check-circle me-2"></i> Low Risk Detected</h6>
                        <p class="mb-0">This URL has been classified as likely legitimate with ${(data.confidence * 100).toFixed(2)}% confidence.</p>
                    </div>
                `;
                
                // Add general safety tips
                insights += `
                    <div class="security-tip mb-2">
                        <strong>Security Reminder:</strong> Even for URLs classified as safe, always be cautious when entering personal information or credentials.
                    </div>
                `;
            }
            
            securityInsights.innerHTML = insights;
        }
    }
    
    // Function to update analytics with new result
    function updateAnalyticsWithNewResult(data) {
        // Add to history
        analysisHistory.push({
            url: data.url,
            timestamp: Date.now(),
            is_phishing: data.is_phishing,
            confidence: data.confidence
        });
        
        // Keep only the last 50 entries
        if (analysisHistory.length > 50) {
            analysisHistory.shift();
        }
        
        // Update counts
        totalAnalyzedCount++;
        if (data.is_phishing) {
            phishingDetectedCount++;
        }
        confidenceSum += data.confidence;
        
        // Save to localStorage
        localStorage.setItem('analysisHistory', JSON.stringify(analysisHistory));
        localStorage.setItem('totalAnalyzedCount', totalAnalyzedCount);
        localStorage.setItem('phishingDetectedCount', phishingDetectedCount);
        localStorage.setItem('confidenceSum', confidenceSum);
        
        // Update analytics display
        updateAnalytics();
        
        // Update charts
        updateAnalyticsCharts();
    }
    
    // Function to update analytics display
    function updateAnalytics() {
        if (totalAnalyzed) {
            totalAnalyzed.textContent = totalAnalyzedCount;
        }
        
        if (phishingDetected) {
            phishingDetected.textContent = phishingDetectedCount;
        }
        
        if (avgConfidence) {
            const average = totalAnalyzedCount > 0 ? (confidenceSum / totalAnalyzedCount) * 100 : 0;
            avgConfidence.textContent = `${average.toFixed(1)}%`;
        }
        
        if (detectionRate) {
            const rate = totalAnalyzedCount > 0 ? (phishingDetectedCount / totalAnalyzedCount) * 100 : 0;
            detectionRate.textContent = `${rate.toFixed(1)}%`;
        }
    }
    
    // Function to update analytics charts
    function updateAnalyticsCharts() {
        // Update history chart
        const historyData = getHistoryChartData();
        updateHistoryChart(historyData);
        
        // Update threat distribution chart
        const threatData = getThreatDistributionData();
        updateThreatDistributionChart(threatData);
    }
    
    // Get history chart data
    function getHistoryChartData() {
        // Group analysis history by day
        const last7Days = Array(7).fill().map((_, i) => {
            const date = new Date();
            date.setDate(date.getDate() - (6 - i));
            return date.toISOString().split('T')[0];
        });
        
        // Initialize counts
        const phishingCounts = Object.fromEntries(last7Days.map(day => [day, 0]));
        const safeCounts = Object.fromEntries(last7Days.map(day => [day, 0]));
        
        // Count entries
        analysisHistory.forEach(entry => {
            const day = new Date(entry.timestamp).toISOString().split('T')[0];
            if (last7Days.includes(day)) {
                if (entry.is_phishing) {
                    phishingCounts[day]++;
                } else {
                    safeCounts[day]++;
                }
            }
        });
        
        // Format for chart
        return {
            labels: last7Days.map(day => formatDate(day)),
            datasets: [
                {
                    label: 'Safe URLs',
                    data: Object.values(safeCounts),
                    backgroundColor: 'rgba(25, 135, 84, 0.7)',
                    borderColor: 'rgba(25, 135, 84, 1)',
                    borderWidth: 1
                },
                {
                    label: 'Phishing URLs',
                    data: Object.values(phishingCounts),
                    backgroundColor: 'rgba(220, 53, 69, 0.7)',
                    borderColor: 'rgba(220, 53, 69, 1)',
                    borderWidth: 1
                }
            ]
        };
    }
    
    // Format date for display
    function formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }
    
    // Create history chart
    function createHistoryChart(data) {
        if (!historyChart) return;
        
        const ctx = historyChart.getContext('2d');
        historyChartInstance = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true
                    },
                    y: {
                        stacked: true,
                        title: {
                            display: true,
                            text: 'URLs Analyzed'
                        }
                    }
                }
            }
        });
    }
    
    // Update history chart
    function updateHistoryChart(data) {
        if (!historyChartInstance) {
            createHistoryChart(data);
            return;
        }
        
        historyChartInstance.data.labels = data.labels;
        historyChartInstance.data.datasets = data.datasets;
        historyChartInstance.update();
    }
    
    // Get threat distribution data
    function getThreatDistributionData() {
        // Count by threat type
        const safeCount = totalAnalyzedCount - phishingDetectedCount;
        
        return {
            labels: ['Safe', 'Phishing'],
            datasets: [
                {
                    data: [safeCount, phishingDetectedCount],
                    backgroundColor: ['rgba(25, 135, 84, 0.7)', 'rgba(220, 53, 69, 0.7)'],
                    borderColor: ['rgba(25, 135, 84, 1)', 'rgba(220, 53, 69, 1)'],
                    borderWidth: 1
                }
            ]
        };
    }
    
    // Create threat distribution chart
    function createThreatDistributionChart(data) {
        if (!threatDistributionChart) return;
        
        const ctx = threatDistributionChart.getContext('2d');
        threatDistributionChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? (value / total * 100).toFixed(1) + '%' : '0%';
                                return `${label}: ${value} (${percentage})`;
                            }
                        }
                    }
                }
            }
        });
    }
    
    // Update threat distribution chart
    function updateThreatDistributionChart(data) {
        if (!threatDistributionChartInstance) {
            createThreatDistributionChart(data);
            return;
        }
        
        threatDistributionChartInstance.data = data;
        threatDistributionChartInstance.update();
    }
});
