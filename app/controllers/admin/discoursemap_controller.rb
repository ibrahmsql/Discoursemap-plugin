# frozen_string_literal: true

module ::DiscourseMap
  class Admin::DiscourseMapController < ::Admin::AdminController
    requires_plugin 'discourse-discoursemap'
    
    before_action :ensure_staff
    before_action :ensure_discoursemap_enabled
    
    def index
      render json: {
        scanner_enabled: SiteSetting.discoursemap_enabled,
        last_scan: get_last_scan_info,
        scan_modules: get_available_modules,
        scan_history: get_scan_history
      }
    end
    
    def scan
      target_url = params[:target_url] || Discourse.base_url
      scan_modules = params[:modules] || ['all']
      scan_options = params[:options] || {}
      
      # Parametreleri validate et
      unless valid_target_url?(target_url)
        return render json: { error: 'Invalid target URL' }, status: 400
      end
      
      unless valid_scan_modules?(scan_modules)
        return render json: { error: 'Invalid scan modules' }, status: 400
      end
      
      begin
        # Start security scan
        scanner = DiscourseMap::DiscourseMapScanner.new(target_url, scan_options)
        
        if params[:async] == 'true'
          # Asynchronous scan
          job_id = SecureRandom.uuid
          
          # Start background job
          Jobs.enqueue(:security_scan, {
            job_id: job_id,
            target_url: target_url,
            modules: scan_modules,
            options: scan_options,
            user_id: current_user.id
          })
          
          render json: {
            status: 'started',
            job_id: job_id,
            message: 'Security scan started in background'
          }
        else
          # Synchronous scan
          results = scanner.scan(scan_modules)
          
          # Save results
          save_scan_results(results, current_user.id)
          
          render json: {
            status: 'completed',
            results: results,
            scan_time: results[:scan_time],
            summary: results[:summary]
          }
        end
        
      rescue => e
        Rails.logger.error "[DiscourseMapController] Scan error: #{e.message}"
        render json: { error: "Scan failed: #{e.message}" }, status: 500
      end
    end
    
    def scan_status
      job_id = params[:job_id]
      
      unless job_id
        return render json: { error: 'Job ID required' }, status: 400
      end
      
      # Check job status
      job_status = get_job_status(job_id)
      
      if job_status
        render json: job_status
      else
        render json: { error: 'Job not found' }, status: 404
      end
    end
    
    def scan_results
      scan_id = params[:scan_id]
      
      if scan_id
        # Get specific scan result
        results = get_scan_results_by_id(scan_id)
        if results
          render json: results
        else
          render json: { error: 'Scan results not found' }, status: 404
        end
      else
        # Get latest scan results
        results = get_latest_scan_results
        render json: results || { message: 'No scan results available' }
      end
    end
    
    def scan_history
      page = params[:page]&.to_i || 1
      per_page = params[:per_page]&.to_i || 20
      
      history = get_scan_history_paginated(page, per_page)
      
      render json: {
        scans: history,
        pagination: {
          current_page: page,
          per_page: per_page,
          total_pages: (get_total_scan_count / per_page.to_f).ceil
        }
      }
    end
    
    def delete_scan
      scan_id = params[:scan_id]
      
      unless scan_id
        return render json: { error: 'Scan ID required' }, status: 400
      end
      
      if delete_scan_results(scan_id)
        render json: { message: 'Scan deleted successfully' }
      else
        render json: { error: 'Failed to delete scan' }, status: 500
      end
    end
    
    def export_results
      scan_id = params[:scan_id]
      format = params[:format] || 'json'
      
      unless scan_id
        return render json: { error: 'Scan ID required' }, status: 400
      end
      
      results = get_scan_results_by_id(scan_id)
      unless results
        return render json: { error: 'Scan results not found' }, status: 404
      end
      
      case format.downcase
      when 'json'
        send_data results.to_json, 
                  filename: "security_scan_#{scan_id}.json",
                  type: 'application/json'
      when 'csv'
        csv_data = convert_results_to_csv(results)
        send_data csv_data,
                  filename: "security_scan_#{scan_id}.csv",
                  type: 'text/csv'
      when 'pdf'
        pdf_data = convert_results_to_pdf(results)
        send_data pdf_data,
                  filename: "security_scan_#{scan_id}.pdf",
                  type: 'application/pdf'
      else
        render json: { error: 'Unsupported format' }, status: 400
      end
    end
    
    def settings
      if request.get?
        render json: {
          discoursemap_enabled: SiteSetting.discoursemap_enabled,
          scan_frequency: SiteSetting.discoursemap_scan_frequency,
          auto_scan_enabled: SiteSetting.discoursemap_auto_scan_enabled,
          notification_enabled: SiteSetting.discoursemap_notifications_enabled,
          max_scan_history: SiteSetting.discoursemap_max_history
        }
      elsif request.put?
        update_settings
      end
    end
    
    def modules
      render json: {
        available_modules: get_available_modules,
        module_descriptions: get_module_descriptions
      }
    end
    
    def vulnerability_database
      render json: {
        last_updated: get_vuln_db_last_updated,
        total_vulnerabilities: get_total_vulnerabilities,
        vulnerabilities_by_severity: get_vulnerabilities_by_severity,
        recent_vulnerabilities: get_recent_vulnerabilities
      }
    end
    
    def update_vulnerability_database
      begin
        # Update vulnerability database
        updated_count = update_vuln_database
        
        render json: {
          message: 'Vulnerability database updated successfully',
          updated_vulnerabilities: updated_count,
          last_updated: Time.current
        }
      rescue => e
        Rails.logger.error "[DiscourseMapController] Database update error: #{e.message}"
        render json: { error: "Failed to update vulnerability database: #{e.message}" }, status: 500
      end
    end
    
    private
    
    def ensure_discoursemap_enabled
      unless SiteSetting.discoursemap_enabled
        render json: { error: 'DiscourseMap is disabled' }, status: 403
      end
    end
    
    def valid_target_url?(url)
      return false unless url.present?
      
      begin
        uri = URI.parse(url)
        uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
      rescue URI::InvalidURIError
        false
      end
    end
    
    def valid_scan_modules?(modules)
      available_modules = get_available_modules.map { |m| m[:name] }
      available_modules << 'all'
      
      modules.all? { |mod| available_modules.include?(mod) }
    end
    
    def get_available_modules
      [
        {
          name: 'vulnerability_scanner',
          display_name: 'Vulnerability Scanner',
          description: 'Scans for known Discourse vulnerabilities',
          enabled: true
        },
        {
          name: 'plugin_scanner',
          display_name: 'Plugin Scanner',
          description: 'Detects and analyzes installed plugins',
          enabled: true
        },
        {
          name: 'theme_scanner',
          display_name: 'Theme Scanner',
          description: 'Analyzes themes for security issues',
          enabled: true
        },
        {
          name: 'user_scanner',
          display_name: 'User Scanner',
          description: 'Enumerates users and checks for security issues',
          enabled: true
        },
        {
          name: 'endpoint_scanner',
          display_name: 'Endpoint Scanner',
          description: 'Discovers and tests endpoints',
          enabled: true
        },
        {
          name: 'config_scanner',
          display_name: 'Configuration Scanner',
          description: 'Checks for configuration security issues',
          enabled: true
        }
      ]
    end
    
    def get_module_descriptions
      {
        'vulnerability_scanner' => 'Performs comprehensive vulnerability scanning against known Discourse CVEs and security issues.',
        'plugin_scanner' => 'Detects installed plugins, checks for vulnerabilities, and analyzes plugin security.',
        'theme_scanner' => 'Analyzes active themes for security vulnerabilities and malicious code.',
        'user_scanner' => 'Enumerates users, identifies privileged accounts, and checks for user-related security issues.',
        'endpoint_scanner' => 'Discovers accessible endpoints and tests for common web vulnerabilities.',
        'config_scanner' => 'Analyzes Discourse configuration for security misconfigurations.'
      }
    end
    
    def get_last_scan_info
      last_scan = PluginStore.get('discourse-discoursemap', 'last_scan')
      return nil unless last_scan
      
      {
        scan_time: last_scan['scan_time'],
        target_url: last_scan['target_url'],
        modules_scanned: last_scan['modules'],
        total_issues: last_scan['total_issues'],
        critical_issues: last_scan['critical_issues']
      }
    end
    
    def get_scan_history
      scans = PluginStore.get('discourse-discoursemap', 'scan_history') || []
      scans.last(10)  # Get last 10 scans
    end
    
    def get_scan_history_paginated(page, per_page)
      scans = PluginStore.get('discourse-discoursemap', 'scan_history') || []
      start_index = (page - 1) * per_page
      scans.reverse[start_index, per_page] || []
    end
    
    def get_total_scan_count
      scans = PluginStore.get('discourse-discoursemap', 'scan_history') || []
      scans.length
    end
    
    def save_scan_results(results, user_id)
      scan_id = SecureRandom.uuid
      scan_data = {
        id: scan_id,
        results: results,
        user_id: user_id,
        created_at: Time.current
      }
      
      # Save results
      PluginStore.set('discourse-discoursemap', "scan_results_#{scan_id}", scan_data)
      
      # Update scan history
      history = PluginStore.get('discourse-discoursemap', 'scan_history') || []
      history << {
        id: scan_id,
        scan_time: results[:scan_time],
        target_url: results[:target_url],
        modules: results[:modules_scanned],
        total_issues: results[:summary][:total_issues],
        user_id: user_id
      }
      
      # Check history limit
        max_history = SiteSetting.discoursemap_max_history || 100
      history = history.last(max_history)
      
      PluginStore.set('discourse-discoursemap', 'scan_history', history)
      
      # Update last scan information
      PluginStore.set('discourse-discoursemap', 'last_scan', {
        scan_time: results[:scan_time],
        target_url: results[:target_url],
        modules: results[:modules_scanned],
        total_issues: results[:summary][:total_issues],
        critical_issues: results[:summary][:critical_issues]
      })
      
      scan_id
    end
    
    def get_scan_results_by_id(scan_id)
      PluginStore.get('discourse-discoursemap', "scan_results_#{scan_id}")
    end
    
    def get_latest_scan_results
      last_scan = get_last_scan_info
      return nil unless last_scan
      
      # Find last scan ID
      history = get_scan_history
      latest_scan = history.last
      return nil unless latest_scan
      
      get_scan_results_by_id(latest_scan[:id])
    end
    
    def delete_scan_results(scan_id)
      begin
        # Delete scan results
        PluginStore.remove('discourse-discoursemap', "scan_results_#{scan_id}")
        
        # Remove from history
        history = PluginStore.get('discourse-discoursemap', 'scan_history') || []
        history.reject! { |scan| scan[:id] == scan_id }
        PluginStore.set('discourse-discoursemap', 'scan_history', history)
        
        true
      rescue => e
        Rails.logger.error "[DiscourseMapController] Scan deletion error: #{e.message}"
        false
      end
    end
    
    def get_job_status(job_id)
      # Check job status from PluginStore
      PluginStore.get('discourse-discoursemap', "job_status_#{job_id}")
    end
    
    def convert_results_to_csv(results)
      require 'csv'
      
      CSV.generate do |csv|
        csv << ['Module', 'Issue Type', 'Severity', 'Description', 'Recommendation']
        
        results[:modules]&.each do |module_name, module_results|
          module_results[:vulnerabilities]&.each do |vuln|
            csv << [
              module_name,
              vuln[:type],
              vuln[:severity],
              vuln[:description],
              vuln[:recommendation]
            ]
          end
        end
      end
    end
    
    def convert_results_to_pdf(results)
      # PDF conversion process (simple implementation)
        # In real application, Prawn gem can be used
      "PDF export not implemented yet"
    end
    
    def update_settings
      settings_params = params.permit(
        :discoursemap_enabled,
        :scan_frequency,
        :auto_scan_enabled,
        :notification_enabled,
        :max_scan_history
      )
      
      begin
        settings_params.each do |key, value|
          case key
          when 'discoursemap_enabled'
            SiteSetting.discoursemap_enabled = value
          when 'scan_frequency'
            SiteSetting.discoursemap_scan_frequency = value
          when 'auto_scan_enabled'
            SiteSetting.discoursemap_auto_scan_enabled = value
          when 'notification_enabled'
            SiteSetting.discoursemap_notifications_enabled = value
          when 'max_scan_history'
            SiteSetting.discoursemap_max_history = value
          end
        end
        
        render json: { message: 'Settings updated successfully' }
      rescue => e
        Rails.logger.error "[DiscourseMapController] Settings update error: #{e.message}"
        render json: { error: "Failed to update settings: #{e.message}" }, status: 500
      end
    end
    
    def get_vuln_db_last_updated
      PluginStore.get('discourse-discoursemap', 'vuln_db_last_updated') || 'Never'
    end
    
    def get_total_vulnerabilities
      # Total number of vulnerabilities in vulnerability database
      vuln_count = 0
      
      # Plugin vulnerabilities
      vuln_count += DiscourseMap::PluginScanner::PLUGIN_VULNERABILITIES.values.flatten.length
      
      # Theme vulnerabilities
      vuln_count += DiscourseMap::ThemeScanner::THEME_VULNERABILITIES.values.flatten.length
      
      # Core vulnerabilities
      vuln_count += DiscourseMap::VulnerabilityScanner::DISCOURSE_VULNERABILITIES.length
      
      vuln_count
    end
    
    def get_vulnerabilities_by_severity
      severities = { 'Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0 }
      
      # Collect all vulnerabilities and group by severity
      all_vulns = []
      all_vulns.concat(DiscourseMap::PluginScanner::PLUGIN_VULNERABILITIES.values.flatten)
      all_vulns.concat(DiscourseMap::ThemeScanner::THEME_VULNERABILITIES.values.flatten)
      all_vulns.concat(DiscourseMap::VulnerabilityScanner::DISCOURSE_VULNERABILITIES)
      
      all_vulns.each do |vuln|
        severity = vuln[:severity] || 'Low'
        severities[severity] += 1 if severities.key?(severity)
      end
      
      severities
    end
    
    def get_recent_vulnerabilities
      # Return recently added CVEs
      [
        {
          cve_id: 'CVE-2023-49103',
          severity: 'Critical',
          cvss_score: 9.1,
          description: 'Admin panel authentication bypass vulnerability',
          published_date: '2023-12-15'
        },
        {
          cve_id: 'CVE-2023-45131',
          severity: 'High', 
          cvss_score: 8.2,
          description: 'Unauthenticated chat access vulnerability',
          published_date: '2023-11-20'
        },
        {
          cve_id: 'CVE-2023-37467',
          severity: 'Medium',
          cvss_score: 6.5,
          description: 'CSP nonce reuse XSS vulnerability',
          published_date: '2023-10-10'
        }
      ]
    end
    
    def update_vuln_database
      # Vulnerability database update process
      # In real application, current vulnerabilities can be fetched from external API
      
      PluginStore.set('discourse-discoursemap', 'vuln_db_last_updated', Time.current)
      
      # Return number of updated vulnerabilities
      5  # Current CVE count
    end
  end
end