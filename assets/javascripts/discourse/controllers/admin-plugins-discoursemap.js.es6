import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { inject as service } from "@ember/service";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import I18n from "I18n";

export default class AdminPluginsDiscourseMapController extends Controller {
  @service dialog;
  @service router;
  
  @tracked isScanning = false;
  @tracked scanResults = null;
  @tracked scanHistory = [];
  @tracked selectedModules = [];
  @tracked targetUrl = "";
  @tracked scanOptions = {
    aggressive: false,
    includeLowSeverity: true,
    followRedirects: true
  };
  @tracked currentJobId = null;
  @tracked jobStatus = null;
  @tracked scanProgress = 0;
  @tracked currentModule = "";
  @tracked availableModules = [
    {
      name: "vulnerability",
      displayName: "Vulnerability Scanner",
      description: "Scans for known Discourse vulnerabilities and security issues",
      enabled: true
    },
    {
      name: "endpoint",
      displayName: "Endpoint Scanner", 
      description: "Checks for exposed endpoints and sensitive information",
      enabled: true
    },
    {
      name: "config",
      displayName: "Configuration Scanner",
      description: "Analyzes site settings and server configuration",
      enabled: true
    },
    {
      name: "database",
      displayName: "Database Scanner",
      description: "Checks database security and configuration",
      enabled: true
    },
    {
      name: "file",
      displayName: "File Scanner",
      description: "Scans for sensitive files and backup exposure",
      enabled: true
    },
    {
      name: "network",
      displayName: "Network Scanner",
      description: "Performs network security checks and port scanning",
      enabled: true
    }
  ];
  
  init() {
    super.init(...arguments);
    this.selectedModules = this.availableModules.map(m => m.name);
    this.targetUrl = window.location.origin;
    this.loadInitialData();
  }
  
  async loadInitialData() {
    try {
      // Load scanner status and history
      const scannerInfo = await ajax("/admin/plugins/discoursemap");
      this.scanHistory = scannerInfo.scan_history || [];
      
      // Check if there's an active scan
      if (scannerInfo.active_scan) {
        this.isScanning = true;
        this.currentJobId = scannerInfo.active_scan.job_id;
        this.startPolling();
      }
      
    } catch (error) {
      console.error("Failed to load scanner data:", error);
    }
  }
  
  @action
  async startScan() {
    if (this.isScanning) return;
    
    if (!this.targetUrl) {
      this.dialog.alert("Target URL is required");
      return;
    }
    
    if (this.selectedModules.length === 0) {
      this.dialog.alert("At least one scan module must be selected");
      return;
    }
    
    this.isScanning = true;
    this.scanResults = null;
    this.currentJobId = null;
    this.scanProgress = 0;
    this.currentModule = "";
    
    try {
      const response = await ajax("/admin/plugins/discoursemap/scan", {
        type: "POST",
        data: {
          target_url: this.targetUrl,
          modules: this.selectedModules,
          options: this.scanOptions
        }
      });
      
      if (response.status === "started") {
        this.currentJobId = response.job_id;
        this.startPolling();
      } else if (response.status === "completed") {
        this.scanResults = response.results;
        this.isScanning = false;
        this.loadScanHistory();
      }
      
    } catch (error) {
      this.isScanning = false;
      popupAjaxError(error);
    }
  }
  
  @action
  async stopScan() {
    if (!this.currentJobId) return;
    
    try {
      await ajax(`/admin/plugins/discoursemap/stop/${this.currentJobId}`, {
        type: "POST"
      });
      
      this.isScanning = false;
      this.currentJobId = null;
      this.scanProgress = 0;
      this.currentModule = "";
      
    } catch (error) {
      popupAjaxError(error);
    }
  }
  
  startPolling() {
    if (!this.currentJobId || !this.isScanning) return;
    
    this.pollTimer = setInterval(() => {
      this.pollJobStatus();
    }, 2000);
  }
  
  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }
  
  async pollJobStatus() {
    if (!this.currentJobId || !this.isScanning) {
      this.stopPolling();
      return;
    }
    
    try {
      const response = await ajax(`/admin/plugins/discoursemap/scan-status/${this.currentJobId}`);
      
      this.scanProgress = response.progress || 0;
      this.currentModule = response.current_module || "";
      
      if (response.status === "completed") {
        this.isScanning = false;
        this.scanResults = response.results;
        this.scanProgress = 100;
        this.currentModule = "";
        this.stopPolling();
        this.loadScanHistory();
      } else if (response.status === "failed") {
        this.isScanning = false;
        this.scanProgress = 0;
        this.currentModule = "";
        this.stopPolling();
        this.dialog.alert(`Scan failed: ${response.error || "Unknown error"}`);
      }
      
    } catch (error) {
      this.isScanning = false;
      this.scanProgress = 0;
      this.currentModule = "";
      this.stopPolling();
      console.error("Failed to poll scan status:", error);
    }
  }
  
  @action
  async loadScanResults(scanId) {
    try {
      const response = await ajax(`/admin/plugins/discoursemap/results/${scanId}`);
      this.scanResults = response.results;
    } catch (error) {
      popupAjaxError(error);
    }
  }
  
  @action
  async loadScanHistory() {
    try {
      const response = await ajax("/admin/plugins/discoursemap/history");
      this.scanHistory = response.scans || [];
    } catch (error) {
      console.error("Failed to load scan history:", error);
    }
  }
  
  @action
  async deleteScan(scanId) {
    const confirmed = await this.dialog.confirm(
      "Are you sure you want to delete this scan?"
    );
    
    if (!confirmed) return;
    
    try {
      await ajax(`/admin/plugins/discoursemap/scan/${scanId}`, {
        type: "DELETE"
      });
      
      this.loadScanHistory();
      
      if (this.scanResults?.id === scanId) {
        this.scanResults = null;
      }
      
    } catch (error) {
      popupAjaxError(error);
    }
  }
  
  @action
  async exportResults(format) {
    if (!this.scanResults) return;
    
    try {
      const response = await ajax(`/admin/plugins/discoursemap/export/${this.scanResults.id}`, {
        type: "GET",
        data: { format }
      });
      
      // Create download link
      const blob = new Blob([response], { type: this.getContentType(format) });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security_scan_${this.scanResults.id}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
    } catch (error) {
      popupAjaxError(error);
    }
  }
  
  @action
  toggleModule(moduleName) {
    if (this.selectedModules.includes(moduleName)) {
      this.selectedModules = this.selectedModules.filter(m => m !== moduleName);
    } else {
      this.selectedModules = [...this.selectedModules, moduleName];
    }
  }
  
  @action
  selectAllModules() {
    this.selectedModules = this.availableModules.map(m => m.name);
  }
  
  @action
  deselectAllModules() {
    this.selectedModules = [];
  }
  
  @action
  updateTargetUrl(event) {
    this.targetUrl = event.target.value;
  }
  
  @action
  updateScanOption(key, value) {
    this.scanOptions = {
      ...this.scanOptions,
      [key]: value
    };
  }
  
  @action
  updateSetting(key, value) {
    this.settings = {
      ...this.settings,
      [key]: value
    };
  }
  
  getContentType(format) {
    switch (format) {
      case 'json':
        return 'application/json';
      case 'csv':
        return 'text/csv';
      case 'pdf':
        return 'application/pdf';
      default:
        return 'text/plain';
    }
  }
  
  get hasScanResults() {
    return this.scanResults && Object.keys(this.scanResults).length > 0;
  }
  
  get totalIssues() {
    if (!this.scanResults?.summary) return 0;
    return this.scanResults.summary.total_issues || 0;
  }
  
  get criticalIssues() {
    if (!this.scanResults?.summary) return 0;
    return this.scanResults.summary.critical_issues || 0;
  }
  
  get highIssues() {
    if (!this.scanResults?.summary) return 0;
    return this.scanResults.summary.high_issues || 0;
  }
  
  get mediumIssues() {
    if (!this.scanResults?.summary) return 0;
    return this.scanResults.summary.medium_issues || 0;
  }
  
  get lowIssues() {
    if (!this.scanResults?.summary) return 0;
    return this.scanResults.summary.low_issues || 0;
  }
  
  get scanDuration() {
    if (!this.scanResults) return "";
    return this.scanResults.scan_duration || "";
  }
  
  get formattedScanTime() {
    if (!this.scanResults?.scan_time) return "";
    return new Date(this.scanResults.scan_time).toLocaleString();
  }
  
  get isValidTargetUrl() {
    try {
      new URL(this.targetUrl);
      return true;
    } catch {
      return false;
    }
  }
  
  get canStartScan() {
    return !this.isScanning && this.isValidTargetUrl && this.selectedModules.length > 0;
  }
  
  get riskLevel() {
    if (!this.scanResults?.summary) return "Unknown";
    
    const critical = this.criticalIssues;
    const high = this.highIssues;
    const medium = this.mediumIssues;
    
    if (critical > 0) return "Critical";
    if (high > 0) return "High";
    if (medium > 0) return "Medium";
    return "Low";
  }
  
  get riskScore() {
    if (!this.scanResults?.summary) return 0;
    
    const critical = this.criticalIssues * 10;
    const high = this.highIssues * 7;
    const medium = this.mediumIssues * 4;
    const low = this.lowIssues * 1;
    
    return Math.min(100, critical + high + medium + low);
  }
  
  willDestroy() {
    super.willDestroy(...arguments);
    this.stopPolling();
  }
  
  get scanResultsByModule() {
    if (!this.scanResults?.modules) return [];
    
    return Object.entries(this.scanResults.modules).map(([moduleName, results]) => ({
      name: moduleName,
      displayName: moduleName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      results: results,
      issueCount: results.vulnerabilities?.length || 0,
      criticalCount: results.vulnerabilities?.filter(v => v.severity === 'Critical').length || 0,
      highCount: results.vulnerabilities?.filter(v => v.severity === 'High').length || 0
    }));
  }
  
  get recentScans() {
    return this.scanHistory.slice(0, 5);
  }
  
  get hasRecentScans() {
    return this.scanHistory.length > 0;
  }
}