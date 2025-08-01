# frozen_string_literal: true

module DiscourseMap
  class DiscourseMapScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :scan_id, :results, :status, :progress
    
    SCAN_MODULES = [
      'vulnerability_scanner',
      'plugin_scanner', 
      'theme_scanner',
      'user_scanner',
      'endpoint_scanner',
      'config_scanner',
      'database_scanner',
      'file_scanner',
      'network_scanner'
    ].freeze
    
    def initialize(target_url = nil)
      @target_url = target_url || Discourse.base_url
      @scan_id = SecureRandom.uuid
      @results = {
        scan_info: {
          scan_id: @scan_id,
          target_url: @target_url,
          start_time: Time.current,
          end_time: nil,
          duration: nil,
          status: 'initialized',
          total_vulnerabilities: 0,
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0
        },
        modules: {}
      }
      @status = 'initialized'
      @progress = 0
    end
    
    def start_scan(modules: SCAN_MODULES, options: {})
      @status = 'running'
      @results[:scan_info][:start_time] = Time.current
      @results[:scan_info][:status] = 'running'
      
      Rails.logger.info "[DiscourseMap] Security scan started: #{@scan_id}"
      
      begin
        total_modules = modules.length
        completed_modules = 0
        
        modules.each do |module_name|
          Rails.logger.info "[DiscourseMap] Running module: #{module_name}"
          
          scanner_class = get_scanner_class(module_name)
          if scanner_class
            scanner = scanner_class.new(@target_url, options)
            module_results = scanner.scan
            
            @results[:modules][module_name] = module_results
            
            # Update vulnerability counts
            update_vulnerability_counts(module_results)
          else
            Rails.logger.warn "[DiscourseMap] Module not found: #{module_name}"
          end
          
          completed_modules += 1
          @progress = (completed_modules.to_f / total_modules * 100).round(2)
        end
        
        @status = 'completed'
        @results[:scan_info][:status] = 'completed'
        @results[:scan_info][:end_time] = Time.current
        @results[:scan_info][:duration] = calculate_duration
        
        # Save results to database
        save_results
        
        Rails.logger.info "[DiscourseMap] Scan completed: #{@scan_id}"
        
      rescue => e
        @status = 'failed'
        @results[:scan_info][:status] = 'failed'
        @results[:scan_info][:error] = e.message
        
        Rails.logger.error "[DiscourseMap] Scan error: #{e.message}"
        Rails.logger.error e.backtrace.join("\n")
      end
      
      @results
    end
    
    def get_scan_status
      {
        scan_id: @scan_id,
        status: @status,
        progress: @progress,
        current_time: Time.current
      }
    end
    
    def get_results
      @results
    end
    
    def generate_report(format: 'json')
      case format.to_s.downcase
      when 'json'
        @results.to_json
      when 'html'
        ReportGenerator.new(@results).generate_html_report
      when 'pdf'
        ReportGenerator.new(@results).generate_pdf_report
      when 'csv'
        ReportGenerator.new(@results).generate_csv_report
      else
        @results.to_json
      end
    end
    
    private
    
    def get_scanner_class(module_name)
      case module_name
      when 'vulnerability_scanner'
        DiscourseMap::VulnerabilityScanner
      when 'plugin_scanner'
        DiscourseMap::PluginScanner
      when 'theme_scanner'
        DiscourseMap::ThemeScanner
      when 'user_scanner'
        DiscourseMap::UserScanner
      when 'endpoint_scanner'
        DiscourseMap::EndpointScanner
      when 'config_scanner'
        DiscourseMap::ConfigScanner
      when 'database_scanner'
        DiscourseMap::DatabaseScanner
      when 'file_scanner'
        DiscourseMap::FileScanner
      when 'network_scanner'
        DiscourseMap::NetworkScanner
      else
        nil
      end
    end
    
    def update_vulnerability_counts(module_results)
      return unless module_results && module_results[:vulnerabilities]
      
      module_results[:vulnerabilities].each do |vuln|
        severity = vuln[:severity]&.downcase
        @results[:scan_info][:total_vulnerabilities] += 1
        
        case severity
        when 'critical'
          @results[:scan_info][:critical_count] += 1
        when 'high'
          @results[:scan_info][:high_count] += 1
        when 'medium'
          @results[:scan_info][:medium_count] += 1
        when 'low'
          @results[:scan_info][:low_count] += 1
        end
      end
    end
    
    def calculate_duration
      return nil unless @results[:scan_info][:start_time] && @results[:scan_info][:end_time]
      
      duration_seconds = @results[:scan_info][:end_time] - @results[:scan_info][:start_time]
      {
        seconds: duration_seconds.round(2),
        formatted: Time.at(duration_seconds).utc.strftime("%H:%M:%S")
      }
    end
    
    def save_results
      # Store results in PluginStore
      PluginStore.set(
        'discourse-discoursemap',
        "scan_result_#{@scan_id}",
        @results
      )
      
      # Also store the latest scan result
      PluginStore.set(
        'discourse-discoursemap',
        'latest_scan_result',
        {
          scan_id: @scan_id,
          timestamp: Time.current,
          summary: {
            total_vulnerabilities: @results[:scan_info][:total_vulnerabilities],
            critical_count: @results[:scan_info][:critical_count],
            high_count: @results[:scan_info][:high_count],
            medium_count: @results[:scan_info][:medium_count],
            low_count: @results[:scan_info][:low_count]
          }
        }
      )
    end
    
    def self.get_latest_scan
      PluginStore.get('discourse-discoursemap', 'latest_scan_result')
    end
    
    def self.get_scan_result(scan_id)
      PluginStore.get('discourse-discoursemap', "scan_result_#{scan_id}")
    end
    
    def self.clear_all_results
      # Clear all scan results
      PluginStore.remove('discourse-discoursemap', 'latest_scan_result')
      
      # Clear all keys starting with a specific pattern
      # This may vary depending on Discourse's PluginStore API
    end
  end
end