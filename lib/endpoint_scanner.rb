# frozen_string_literal: true

module DiscourseMap
  class EndpointScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Common Discourse endpoints to scan
    DISCOURSE_ENDPOINTS = [
      '/admin',
      '/admin/dashboard',
      '/admin/users',
      '/admin/plugins',
      '/admin/site_settings',
      '/admin/customize',
      '/admin/logs',
      '/admin/backups',
      '/admin/email',
      '/admin/api',
      '/admin/web_hooks',
      '/admin/badges',
      '/admin/groups',
      '/admin/categories',
      '/admin/tags',
      '/admin/watched_words',
      '/admin/screened_emails',
      '/admin/screened_ip_addresses',
      '/admin/screened_urls',
      '/session',
      '/session/csrf',
      '/session/current',
      '/users',
      '/users.json',
      '/groups',
      '/groups.json',
      '/categories',
      '/categories.json',
      '/latest',
      '/latest.json',
      '/top',
      '/top.json',
      '/search',
      '/search.json',
      '/posts',
      '/posts.json',
      '/topics',
      '/topics.json',
      '/uploads',
      '/uploads.json',
      '/notifications',
      '/notifications.json',
      '/user_actions',
      '/user_actions.json',
      '/directory_items',
      '/directory_items.json',
      '/tags',
      '/tags.json',
      '/badges',
      '/badges.json',
      '/site',
      '/site.json',
      '/site/statistics',
      '/site/statistics.json',
      '/about',
      '/about.json',
      '/privacy',
      '/tos',
      '/faq',
      '/guidelines',
      '/styleguide',
      '/manifest.json',
      '/opensearch.xml',
      '/robots.txt',
      '/sitemap.xml',
      '/.well-known/change-password',
      '/.well-known/security.txt',
      '/api/docs',
      '/api/swagger',
      '/health',
      '/status',
      '/version',
      '/info'
    ].freeze
    
    # Sensitive endpoints that should be protected
    SENSITIVE_ENDPOINTS = [
      '/admin',
      '/admin/dashboard',
      '/admin/users',
      '/admin/plugins',
      '/admin/site_settings',
      '/admin/logs',
      '/admin/backups',
      '/admin/email',
      '/admin/api',
      '/session/csrf',
      '/uploads'
    ].freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
    end
    
    def scan
      results = {
        scan_type: 'endpoint_scan',
        target_url: @target_url,
        timestamp: Time.current,
        total_endpoints: 0,
        accessible_endpoints: [],
        protected_endpoints: [],
        suspicious_endpoints: [],
        vulnerabilities: [],
        recommendations: []
      }
      
      Rails.logger.info "[EndpointScanner] Starting endpoint scan for #{@target_url}"
      
      begin
        # Scan common Discourse endpoints
        scan_discourse_endpoints(results)
        
        # Check for sensitive endpoint protection
        check_sensitive_endpoints(results)
        
        # Look for exposed configuration files
        scan_config_files(results)
        
        # Check for backup files
        scan_backup_files(results)
        
        # Scan for development/debug endpoints
        scan_debug_endpoints(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
        results[:total_endpoints] = results[:accessible_endpoints].length
        
        Rails.logger.info "[EndpointScanner] Endpoint scan completed. Found #{results[:total_endpoints]} accessible endpoints"
        
      rescue => e
        Rails.logger.error "[EndpointScanner] Error during endpoint scan: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def scan_discourse_endpoints(results)
      DISCOURSE_ENDPOINTS.each do |endpoint|
        begin
          response = make_request(endpoint)
          
          if response && response.code.to_i < 400
            endpoint_info = {
              path: endpoint,
              status_code: response.code.to_i,
              content_type: response['content-type'],
              content_length: response['content-length'],
              server: response['server'],
              accessible: true
            }
            
            results[:accessible_endpoints] << endpoint_info
            
            # Check if endpoint contains sensitive information
            if contains_sensitive_info?(response.body)
              results[:suspicious_endpoints] << endpoint_info.merge({
                reason: 'Contains potentially sensitive information'
              })
            end
          else
            results[:protected_endpoints] << {
              path: endpoint,
              status_code: response&.code&.to_i || 0,
              protected: true
            }
          end
          
        rescue => e
          Rails.logger.debug "[EndpointScanner] Error accessing #{endpoint}: #{e.message}"
        end
        
        # Rate limiting
        sleep(0.1) if @options[:rate_limit]
      end
    end
    
    def check_sensitive_endpoints(results)
      SENSITIVE_ENDPOINTS.each do |endpoint|
        accessible_endpoint = results[:accessible_endpoints].find { |ep| ep[:path] == endpoint }
        
        if accessible_endpoint
          vulnerability = {
            type: 'Exposed Sensitive Endpoint',
            severity: 'High',
            endpoint: endpoint,
            description: "Sensitive endpoint #{endpoint} is accessible without proper authentication",
            recommendation: 'Ensure proper authentication and authorization for sensitive endpoints'
          }
          
          results[:vulnerabilities] << vulnerability
        end
      end
    end
    
    def scan_config_files(results)
      config_files = [
        '/.env',
        '/config.json',
        '/config.yml',
        '/config.yaml',
        '/settings.json',
        '/settings.yml',
        '/database.yml',
        '/secrets.yml',
        '/app.yml',
        '/discourse.conf',
        '/nginx.conf',
        '/apache.conf'
      ]
      
      config_files.each do |file|
        begin
          response = make_request(file)
          
          if response && response.code.to_i == 200
            vulnerability = {
              type: 'Exposed Configuration File',
              severity: 'Critical',
              endpoint: file,
              description: "Configuration file #{file} is publicly accessible",
              recommendation: 'Remove or protect configuration files from public access'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
        rescue => e
          Rails.logger.debug "[EndpointScanner] Error checking config file #{file}: #{e.message}"
        end
      end
    end
    
    def scan_backup_files(results)
      backup_extensions = ['.bak', '.backup', '.old', '.orig', '.tmp', '.swp', '~']
      common_files = ['database', 'config', 'settings', 'app', 'discourse']
      
      backup_extensions.each do |ext|
        common_files.each do |file|
          backup_file = "/#{file}#{ext}"
          
          begin
            response = make_request(backup_file)
            
            if response && response.code.to_i == 200
              vulnerability = {
                type: 'Exposed Backup File',
                severity: 'High',
                endpoint: backup_file,
                description: "Backup file #{backup_file} is publicly accessible",
                recommendation: 'Remove backup files from public directories'
              }
              
              results[:vulnerabilities] << vulnerability
            end
            
          rescue => e
            Rails.logger.debug "[EndpointScanner] Error checking backup file #{backup_file}: #{e.message}"
          end
        end
      end
    end
    
    def scan_debug_endpoints(results)
      debug_endpoints = [
        '/debug',
        '/test',
        '/dev',
        '/development',
        '/staging',
        '/phpinfo',
        '/info',
        '/server-info',
        '/server-status',
        '/status',
        '/health',
        '/metrics',
        '/actuator',
        '/console'
      ]
      
      debug_endpoints.each do |endpoint|
        begin
          response = make_request(endpoint)
          
          if response && response.code.to_i == 200
            vulnerability = {
              type: 'Exposed Debug Endpoint',
              severity: 'Medium',
              endpoint: endpoint,
              description: "Debug endpoint #{endpoint} is accessible in production",
              recommendation: 'Disable debug endpoints in production environment'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
        rescue => e
          Rails.logger.debug "[EndpointScanner] Error checking debug endpoint #{endpoint}: #{e.message}"
        end
      end
    end
    
    def make_request(path)
      uri = URI.join(@target_url, path)
      
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = @options[:verify_ssl] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = @options[:timeout] || 10
      http.read_timeout = @options[:timeout] || 10
      
      request = Net::HTTP::Get.new(uri.request_uri)
      request['User-Agent'] = @options[:user_agent] || 'DiscourseMap/1.0'
      
      # Add custom headers if provided
      if @options[:headers]
        @options[:headers].each do |key, value|
          request[key] = value
        end
      end
      
      http.request(request)
    end
    
    def contains_sensitive_info?(content)
      return false unless content
      
      sensitive_patterns = [
        /password/i,
        /secret/i,
        /token/i,
        /api[_-]?key/i,
        /private[_-]?key/i,
        /database/i,
        /connection[_-]?string/i,
        /smtp/i,
        /email[_-]?config/i
      ]
      
      sensitive_patterns.any? { |pattern| content.match?(pattern) }
    end
    
    def generate_recommendations(results)
      recommendations = []
      
      if results[:vulnerabilities].any? { |v| v[:type] == 'Exposed Sensitive Endpoint' }
        recommendations << 'Implement proper authentication and authorization for admin endpoints'
      end
      
      if results[:vulnerabilities].any? { |v| v[:type] == 'Exposed Configuration File' }
        recommendations << 'Move configuration files outside of web root directory'
      end
      
      if results[:vulnerabilities].any? { |v| v[:type] == 'Exposed Backup File' }
        recommendations << 'Remove backup files from public directories'
      end
      
      if results[:vulnerabilities].any? { |v| v[:type] == 'Exposed Debug Endpoint' }
        recommendations << 'Disable debug and development endpoints in production'
      end
      
      if results[:accessible_endpoints].length > 50
        recommendations << 'Consider implementing rate limiting for API endpoints'
      end
      
      results[:recommendations] = recommendations
    end
  end
end