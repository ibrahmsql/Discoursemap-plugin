# frozen_string_literal: true

module DiscourseMap
  class ConfigScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Security-critical site settings to check
    CRITICAL_SETTINGS = {
      'force_https' => {
        expected: true,
        severity: 'High',
        description: 'HTTPS should be enforced for security'
      },
      'enable_sso' => {
        expected: nil,
        severity: 'Medium',
        description: 'SSO configuration should be reviewed'
      },
      'cors_origins' => {
        expected: nil,
        severity: 'Medium',
        description: 'CORS origins should be restricted'
      },
      'content_security_policy' => {
        expected: true,
        severity: 'High',
        description: 'Content Security Policy should be enabled'
      },
      'enable_local_logins' => {
        expected: nil,
        severity: 'Low',
        description: 'Local login settings should be reviewed'
      },
      'min_password_length' => {
        expected: 8,
        severity: 'Medium',
        description: 'Minimum password length should be at least 8 characters'
      },
      'enable_google_logins' => {
        expected: nil,
        severity: 'Low',
        description: 'Third-party login settings should be reviewed'
      },
      'enable_facebook_logins' => {
        expected: nil,
        severity: 'Low',
        description: 'Third-party login settings should be reviewed'
      },
      'enable_twitter_logins' => {
        expected: nil,
        severity: 'Low',
        description: 'Third-party login settings should be reviewed'
      },
      'enable_github_logins' => {
        expected: nil,
        severity: 'Low',
        description: 'Third-party login settings should be reviewed'
      },
      'max_attachment_size_kb' => {
        expected: 10240,
        severity: 'Medium',
        description: 'File upload size should be limited'
      },
      'authorized_extensions' => {
        expected: nil,
        severity: 'Medium',
        description: 'File upload extensions should be restricted'
      },
      'enable_uploads' => {
        expected: nil,
        severity: 'Medium',
        description: 'File upload settings should be reviewed'
      },
      'allow_uncategorized_topics' => {
        expected: false,
        severity: 'Low',
        description: 'Uncategorized topics should be disabled for better organization'
      },
      'enable_whispers' => {
        expected: nil,
        severity: 'Low',
        description: 'Whisper feature settings should be reviewed'
      },
      'max_username_length' => {
        expected: 20,
        severity: 'Low',
        description: 'Username length should be limited'
      },
      'min_username_length' => {
        expected: 3,
        severity: 'Low',
        description: 'Minimum username length should be enforced'
      },
      'enable_names' => {
        expected: nil,
        severity: 'Info',
        description: 'Display name settings should be reviewed'
      },
      'invite_only' => {
        expected: nil,
        severity: 'Medium',
        description: 'Invite-only mode should be considered for private communities'
      },
      'login_required' => {
        expected: nil,
        severity: 'Medium',
        description: 'Login requirement should be reviewed based on community needs'
      },
      'must_approve_users' => {
        expected: nil,
        severity: 'Medium',
        description: 'User approval settings should be reviewed'
      },
      'enable_local_account_create' => {
        expected: nil,
        severity: 'Medium',
        description: 'Local account creation settings should be reviewed'
      }
    }.freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
    end
    
    def scan
      results = {
        scan_type: 'config_scan',
        target_url: @target_url,
        timestamp: Time.current,
        site_settings: {},
        vulnerabilities: [],
        recommendations: [],
        security_score: 0
      }
      
      Rails.logger.info "[ConfigScanner] Starting configuration scan for #{@target_url}"
      
      begin
        # Scan site settings
        scan_site_settings(results)
        
        # Check server configuration
        check_server_config(results)
        
        # Check SSL/TLS configuration
        check_ssl_config(results)
        
        # Check security headers
        check_security_headers(results)
        
        # Check for exposed configuration endpoints
        check_config_endpoints(results)
        
        # Calculate security score
        calculate_security_score(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
        Rails.logger.info "[ConfigScanner] Configuration scan completed. Security score: #{results[:security_score]}/100"
        
      rescue => e
        Rails.logger.error "[ConfigScanner] Error during configuration scan: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def scan_site_settings(results)
      CRITICAL_SETTINGS.each do |setting_name, config|
        begin
          # Try to get setting value (this would need to be adapted based on how settings are accessible)
          setting_value = get_site_setting(setting_name)
          
          results[:site_settings][setting_name] = {
            value: setting_value,
            expected: config[:expected],
            severity: config[:severity],
            description: config[:description]
          }
          
          # Check if setting meets security expectations
          if config[:expected] && setting_value != config[:expected]
            vulnerability = {
              type: 'Insecure Site Setting',
              severity: config[:severity],
              setting: setting_name,
              current_value: setting_value,
              expected_value: config[:expected],
              description: config[:description],
              recommendation: "Update #{setting_name} to recommended value: #{config[:expected]}"
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
        rescue => e
          Rails.logger.debug "[ConfigScanner] Error checking setting #{setting_name}: #{e.message}"
        end
      end
    end
    
    def check_server_config(results)
      begin
        response = make_request('/')
        
        if response
          server_header = response['server']
          
          if server_header
            # Check for server version disclosure
            if server_header.match?(/\d+\.\d+/)
              vulnerability = {
                type: 'Server Version Disclosure',
                severity: 'Low',
                description: "Server header reveals version information: #{server_header}",
                recommendation: 'Configure server to hide version information'
              }
              
              results[:vulnerabilities] << vulnerability
            end
            
            results[:site_settings]['server_header'] = {
              value: server_header,
              description: 'Server identification header'
            }
          end
          
          # Check for powered-by headers
          powered_by = response['x-powered-by']
          if powered_by
            vulnerability = {
              type: 'Technology Disclosure',
              severity: 'Low',
              description: "X-Powered-By header reveals technology stack: #{powered_by}",
              recommendation: 'Remove X-Powered-By header to reduce information disclosure'
            }
            
            results[:vulnerabilities] << vulnerability
          end
        end
        
      rescue => e
        Rails.logger.debug "[ConfigScanner] Error checking server config: #{e.message}"
      end
    end
    
    def check_ssl_config(results)
      return unless @target_url.start_with?('https')
      
      begin
        uri = URI(@target_url)
        
        # Check SSL certificate
        tcp_socket = TCPSocket.new(uri.host, uri.port || 443)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.connect
        
        cert = ssl_socket.peer_cert
        
        if cert
          # Check certificate expiration
          days_until_expiry = (cert.not_after - Time.current) / 1.day
          
          if days_until_expiry < 30
            severity = days_until_expiry < 7 ? 'Critical' : 'High'
            vulnerability = {
              type: 'SSL Certificate Expiring',
              severity: severity,
              description: "SSL certificate expires in #{days_until_expiry.to_i} days",
              recommendation: 'Renew SSL certificate before expiration'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
          # Check certificate algorithm
          if cert.signature_algorithm.include?('sha1')
            vulnerability = {
              type: 'Weak SSL Certificate Algorithm',
              severity: 'Medium',
              description: 'SSL certificate uses weak SHA-1 algorithm',
              recommendation: 'Upgrade to certificate with SHA-256 or stronger algorithm'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
          results[:site_settings]['ssl_certificate'] = {
            subject: cert.subject.to_s,
            issuer: cert.issuer.to_s,
            expires: cert.not_after,
            algorithm: cert.signature_algorithm
          }
        end
        
        ssl_socket.close
        tcp_socket.close
        
      rescue => e
        Rails.logger.debug "[ConfigScanner] Error checking SSL config: #{e.message}"
      end
    end
    
    def check_security_headers(results)
      begin
        response = make_request('/')
        
        if response
          security_headers = {
            'strict-transport-security' => 'HSTS header missing',
            'content-security-policy' => 'CSP header missing',
            'x-frame-options' => 'X-Frame-Options header missing',
            'x-content-type-options' => 'X-Content-Type-Options header missing',
            'x-xss-protection' => 'X-XSS-Protection header missing',
            'referrer-policy' => 'Referrer-Policy header missing'
          }
          
          security_headers.each do |header, missing_message|
            header_value = response[header]
            
            if header_value
              results[:site_settings][header] = {
                value: header_value,
                description: "Security header: #{header}"
              }
              
              # Check for weak configurations
              case header
              when 'x-frame-options'
                unless ['DENY', 'SAMEORIGIN'].include?(header_value.upcase)
                  add_header_vulnerability(results, header, 'Weak X-Frame-Options configuration')
                end
              when 'content-security-policy'
                if header_value.include?('unsafe-inline') || header_value.include?('unsafe-eval')
                  add_header_vulnerability(results, header, 'CSP allows unsafe-inline or unsafe-eval')
                end
              end
            else
              vulnerability = {
                type: 'Missing Security Header',
                severity: 'Medium',
                header: header,
                description: missing_message,
                recommendation: "Add #{header} header for enhanced security"
              }
              
              results[:vulnerabilities] << vulnerability
            end
          end
        end
        
      rescue => e
        Rails.logger.debug "[ConfigScanner] Error checking security headers: #{e.message}"
      end
    end
    
    def check_config_endpoints(results)
      config_endpoints = [
        '/site.json',
        '/site/statistics.json',
        '/admin/site_settings.json',
        '/.well-known/security.txt',
        '/manifest.json'
      ]
      
      config_endpoints.each do |endpoint|
        begin
          response = make_request(endpoint)
          
          if response && response.code.to_i == 200
            # Check if endpoint exposes sensitive information
            if endpoint.include?('admin') || endpoint.include?('settings')
              vulnerability = {
                type: 'Exposed Configuration Endpoint',
                severity: 'High',
                endpoint: endpoint,
                description: "Configuration endpoint #{endpoint} is publicly accessible",
                recommendation: 'Restrict access to configuration endpoints'
              }
              
              results[:vulnerabilities] << vulnerability
            end
          end
          
        rescue => e
          Rails.logger.debug "[ConfigScanner] Error checking config endpoint #{endpoint}: #{e.message}"
        end
      end
    end
    
    def get_site_setting(setting_name)
      # This would need to be implemented based on how Discourse exposes settings
      # For now, return nil to indicate setting couldn't be retrieved
      begin
        if defined?(SiteSetting) && SiteSetting.respond_to?(setting_name)
          SiteSetting.send(setting_name)
        else
          nil
        end
      rescue
        nil
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
    
    def add_header_vulnerability(results, header, description)
      vulnerability = {
        type: 'Weak Security Header Configuration',
        severity: 'Medium',
        header: header,
        description: description,
        recommendation: "Review and strengthen #{header} configuration"
      }
      
      results[:vulnerabilities] << vulnerability
    end
    
    def calculate_security_score(results)
      total_checks = CRITICAL_SETTINGS.length + 6 # 6 for security headers
      failed_checks = results[:vulnerabilities].length
      
      score = ((total_checks - failed_checks).to_f / total_checks * 100).round
      results[:security_score] = [score, 0].max
    end
    
    def generate_recommendations(results)
      recommendations = []
      
      # Group vulnerabilities by type
      vuln_types = results[:vulnerabilities].group_by { |v| v[:type] }
      
      if vuln_types['Missing Security Header']
        recommendations << 'Implement missing security headers to protect against common attacks'
      end
      
      if vuln_types['Insecure Site Setting']
        recommendations << 'Review and update site settings to follow security best practices'
      end
      
      if vuln_types['SSL Certificate Expiring']
        recommendations << 'Monitor SSL certificate expiration and set up automatic renewal'
      end
      
      if vuln_types['Server Version Disclosure']
        recommendations << 'Configure web server to hide version information'
      end
      
      if results[:security_score] < 70
        recommendations << 'Overall security configuration needs significant improvement'
      elsif results[:security_score] < 85
        recommendations << 'Security configuration is good but could be enhanced'
      end
      
      results[:recommendations] = recommendations
    end
  end
end