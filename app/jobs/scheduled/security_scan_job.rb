# frozen_string_literal: true

module Jobs
  class SecurityScan < ::Jobs::Scheduled
    every 1.day
    
    def execute(args)
      return unless SiteSetting.discoursemap_enabled
      return unless SiteSetting.security_auto_scan_enabled
      
      target_url = args[:target_url] || Discourse.base_url
      modules = args[:modules] || ['all']
      options = args[:options] || {}
      user_id = args[:user_id] || Discourse.system_user.id
      job_id = args[:job_id] || SecureRandom.uuid
      
      begin
        Rails.logger.info "[SecurityScanJob] Starting security scan for #{target_url}"
        
        # Update job status
        update_job_status(job_id, 'running', 'Security scan started')
        
        # Start security scan
        scanner = DiscourseMap::DiscourseMapScanner.new(target_url, options)
        results = scanner.scan(modules)
        
        # Save results
        scan_id = save_scan_results(results, user_id)
        
        # Update job status
        update_job_status(job_id, 'completed', 'Security scan completed successfully', {
          scan_id: scan_id,
          results_summary: results[:summary]
        })
        
        # Send notification if critical issues found
        if should_send_notification?(results)
          send_security_notification(results, user_id)
        end
        
        Rails.logger.info "[SecurityScanJob] Security scan completed successfully. Scan ID: #{scan_id}"
        
      rescue => e
        Rails.logger.error "[SecurityScanJob] Security scan failed: #{e.message}"
        Rails.logger.error e.backtrace.join("\n")
        
        # Update job status as error
        update_job_status(job_id, 'failed', "Security scan failed: #{e.message}")
        
        # Send error notification
        send_error_notification(e, user_id)
      end
    end
    
    private
    
    def update_job_status(job_id, status, message, data = {})
      job_status = {
        job_id: job_id,
        status: status,
        message: message,
        updated_at: Time.current,
        data: data
      }
      
      PluginStore.set('discourse-discoursemap', "job_status_#{job_id}", job_status)
      
      # Job durumunu 24 saat sonra temizle
      Jobs.enqueue_in(24.hours, :cleanup_job_status, job_id: job_id)
    end
    
    def save_scan_results(results, user_id)
      scan_id = SecureRandom.uuid
      scan_data = {
        id: scan_id,
        results: results,
        user_id: user_id,
        created_at: Time.current,
        scan_type: 'scheduled'
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
        critical_issues: results[:summary][:critical_issues],
        user_id: user_id,
        scan_type: 'scheduled'
      }
      
      # Check history limit
      max_history = SiteSetting.security_scan_max_history || 100
      history = history.last(max_history)
      
      PluginStore.set('discourse-discoursemap', 'scan_history', history)
      
      # Update last scan information
      PluginStore.set('discourse-discoursemap', 'last_scan', {
        scan_time: results[:scan_time],
        target_url: results[:target_url],
        modules: results[:modules_scanned],
        total_issues: results[:summary][:total_issues],
        critical_issues: results[:summary][:critical_issues],
        scan_type: 'scheduled'
      })
      
      scan_id
    end
    
    def should_send_notification?(results)
      return false unless SiteSetting.security_scan_notifications_enabled
      
      # Send notification if critical issues found
      critical_issues = results[:summary][:critical_issues] || 0
      high_issues = results[:summary][:high_issues] || 0
      
      critical_issues > 0 || high_issues > 5
    end
    
    def send_security_notification(results, user_id)
      begin
        user = User.find(user_id)
        
        # Prepare notification message
        notification_data = prepare_notification_data(results)
        
        # Send notification to admin users
        admin_users = User.where(admin: true)
        
        admin_users.each do |admin|
          # Send private message
          PostCreator.create!(
            Discourse.system_user,
            title: "Security Scan Alert - #{notification_data[:severity]} Issues Detected",
            raw: notification_data[:message],
            target_usernames: admin.username,
            archetype: Archetype.private_message
          )
        end
        
        Rails.logger.info "[SecurityScanJob] Security notification sent to #{admin_users.count} admins"
        
      rescue => e
        Rails.logger.error "[SecurityScanJob] Failed to send security notification: #{e.message}"
      end
    end
    
    def send_error_notification(error, user_id)
      return unless SiteSetting.security_scan_notifications_enabled
      
      begin
        # Send error notification to admin users
        admin_users = User.where(admin: true)
        
        error_message = <<~MSG
          **Security Scan Error**
          
          A scheduled security scan has failed with the following error:
          
          ```
          #{error.message}
          ```
          
          **Time:** #{Time.current.strftime('%Y-%m-%d %H:%M:%S UTC')}
          **Target:** #{Discourse.base_url}
            
          Please check the logs for more details and ensure DiscourseMap is properly configured.
        MSG
        
        admin_users.each do |admin|
          PostCreator.create!(
            Discourse.system_user,
            title: "Security Scan Failed",
            raw: error_message,
            target_usernames: admin.username,
            archetype: Archetype.private_message
          )
        end
        
      rescue => e
        Rails.logger.error "[SecurityScanJob] Failed to send error notification: #{e.message}"
      end
    end
    
    def prepare_notification_data(results)
      summary = results[:summary]
      critical_issues = summary[:critical_issues] || 0
      high_issues = summary[:high_issues] || 0
      medium_issues = summary[:medium_issues] || 0
      total_issues = summary[:total_issues] || 0
      
      # Severity seviyesini belirle
      severity = if critical_issues > 0
                   'CRITICAL'
                 elsif high_issues > 0
                   'HIGH'
                 elsif medium_issues > 0
                   'MEDIUM'
                 else
                   'LOW'
                 end
      
      # Prepare notification message
      message = <<~MSG
        **Security Scan Results - #{severity} Priority**
        
        A scheduled security scan has detected potential security issues on your Discourse instance.
        
        **Scan Summary:**
        - **Target:** #{results[:target_url]}
        - **Scan Time:** #{results[:scan_time]}
        - **Total Issues:** #{total_issues}
        
        **Issues by Severity:**
        - 🔴 **Critical:** #{critical_issues}
        - 🟠 **High:** #{high_issues}
        - 🟡 **Medium:** #{medium_issues}
        - 🟢 **Low:** #{summary[:low_issues] || 0}
        
        **Modules Scanned:**
        #{format_scanned_modules(results[:modules_scanned])}
        
        #{format_top_issues(results)}
        
        **Recommendations:**
        1. Review the detailed scan results in the admin panel
        2. Address critical and high-severity issues immediately
        3. Update plugins and themes to latest versions
        4. Review user permissions and access controls
        
        **Next Steps:**
        - Visit `/admin/plugins/discourse-discoursemap` to view detailed results
        - Schedule regular security scans
        - Monitor for new vulnerabilities
        
        ---
        *This is an automated security notification from DiscourseMap*
      MSG
      
      {
        severity: severity,
        message: message,
        critical_issues: critical_issues,
        high_issues: high_issues,
        total_issues: total_issues
      }
    end
    
    def format_scanned_modules(modules)
      return "- All modules" if modules.include?('all')
      
      modules.map { |mod| "- #{mod.humanize}" }.join("\n")
    end
    
    def format_top_issues(results)
      top_issues = []
      
      # Collect most critical issues from each module
      results[:modules]&.each do |module_name, module_results|
        next unless module_results[:vulnerabilities]
        
        critical_vulns = module_results[:vulnerabilities].select { |v| v[:severity] == 'Critical' }
        high_vulns = module_results[:vulnerabilities].select { |v| v[:severity] == 'High' }
        
        critical_vulns.first(2).each do |vuln|
          top_issues << "🔴 **#{vuln[:type]}** in #{module_name.humanize}: #{vuln[:description]}"
        end
        
        high_vulns.first(1).each do |vuln|
          top_issues << "🟠 **#{vuln[:type]}** in #{module_name.humanize}: #{vuln[:description]}"
        end
      end
      
      if top_issues.any?
        "**Top Issues Found:**\n#{top_issues.first(5).join("\n")}\n"
      else
        ""
      end
    end
  end
  
  # Job status temizleme job'u
  class CleanupJobStatus < ::Jobs::Base
    def execute(args)
      job_id = args[:job_id]
      return unless job_id
      
      begin
        PluginStore.remove('discourse-discoursemap', "job_status_#{job_id}")
        Rails.logger.debug "[CleanupJobStatus] Cleaned up job status for #{job_id}"
      rescue => e
        Rails.logger.error "[CleanupJobStatus] Failed to cleanup job status: #{e.message}"
      end
    end
  end
end