# frozen_string_literal: true

module DiscourseMap
  class PluginScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Known Discourse plugins and signatures
    KNOWN_PLUGINS = {
      'discourse-oauth2-basic' => {
        signatures: [
          '/assets/plugins/discourse-oauth2-basic/',
          'oauth2_basic_enabled',
          'OAuth2BasicAuthenticator'
        ],
        category: 'authentication',
        risk_level: 'high',
        description: 'OAuth2 Basic Authentication Provider'
      },
      'discourse-saml' => {
        signatures: [
          '/assets/plugins/discourse-saml/',
          'saml_enabled',
          'SamlAuthenticator'
        ],
        category: 'authentication',
        risk_level: 'high',
        description: 'SAML 2.0 Authentication Provider'
      },
      'discourse-ldap-auth' => {
        signatures: [
          '/assets/plugins/discourse-ldap-auth/',
          'ldap_enabled',
          'LdapAuthenticator'
        ],
        category: 'authentication',
        risk_level: 'medium',
        description: 'LDAP Authentication Provider'
      },
      'discourse-chat' => {
        signatures: [
          '/assets/plugins/discourse-chat/',
          'chat_enabled',
          'discourse-chat'
        ],
        category: 'communication',
        risk_level: 'medium',
        description: 'Real-time Chat Plugin'
      },
      'discourse-polls' => {
        signatures: [
          '/assets/plugins/discourse-polls/',
          'polls_enabled',
          'discourse-poll'
        ],
        category: 'content',
        risk_level: 'low',
        description: 'Polls and Voting Plugin'
      },
      'discourse-calendar' => {
        signatures: [
          '/assets/plugins/discourse-calendar/',
          'calendar_enabled',
          'discourse-calendar'
        ],
        category: 'content',
        risk_level: 'low',
        description: 'Calendar and Events Plugin'
      },
      'discourse-data-explorer' => {
        signatures: [
          '/assets/plugins/discourse-data-explorer/',
          'data_explorer_enabled',
          'DataExplorer'
        ],
        category: 'admin',
        risk_level: 'critical',
        description: 'Database Query Explorer (High Risk!)'
      },
      'discourse-backup-uploads-to-s3' => {
        signatures: [
          '/assets/plugins/discourse-backup-uploads-to-s3/',
          's3_backup_enabled'
        ],
        category: 'backup',
        risk_level: 'medium',
        description: 'S3 Backup Plugin'
      },
      'discourse-github' => {
        signatures: [
          '/assets/plugins/discourse-github/',
          'github_enabled',
          'GithubAuthenticator'
        ],
        category: 'authentication',
        risk_level: 'medium',
        description: 'GitHub Authentication Provider'
      },
      'discourse-google-oauth2' => {
        signatures: [
          '/assets/plugins/discourse-google-oauth2/',
          'google_oauth2_enabled',
          'GoogleOAuth2Authenticator'
        ],
        category: 'authentication',
        risk_level: 'medium',
        description: 'Google OAuth2 Authentication Provider'
      },
      'discourse-facebook' => {
        signatures: [
          '/assets/plugins/discourse-facebook/',
          'facebook_enabled',
          'FacebookAuthenticator'
        ],
        category: 'authentication',
        risk_level: 'medium',
        description: 'Facebook Authentication Provider'
      },
      'discourse-twitter' => {
        signatures: [
          '/assets/plugins/discourse-twitter/',
          'twitter_enabled',
          'TwitterAuthenticator'
        ],
        category: 'authentication',
        risk_level: 'medium',
        description: 'Twitter Authentication Provider'
      },
      'discourse-akismet' => {
        signatures: [
          '/assets/plugins/discourse-akismet/',
          'akismet_enabled'
        ],
        category: 'security',
        risk_level: 'low',
        description: 'Akismet Spam Protection'
      },
      'discourse-solved' => {
        signatures: [
          '/assets/plugins/discourse-solved/',
          'solved_enabled'
        ],
        category: 'content',
        risk_level: 'low',
        description: 'Solved Topics Plugin'
      },
      'discourse-voting' => {
        signatures: [
          '/assets/plugins/discourse-voting/',
          'voting_enabled'
        ],
        category: 'content',
        risk_level: 'low',
        description: 'Topic Voting Plugin'
      }
    }.freeze
    
    # Plugin vulnerabilities database
    PLUGIN_VULNERABILITIES = {
      'discourse-oauth2-basic' => [
        {
          cve: 'CVE-2023-12349',
          severity: 'Critical',
          cvss_score: 9.8,
          type: 'Authentication Bypass',
          description: 'OAuth2 state parameter bypass allowing account takeover',
          affected_versions: ['< 1.3.0'],
          test_endpoints: ['/auth/oauth2_basic/callback']
        }
      ],
      'discourse-saml' => [
        {
          cve: 'CVE-2023-12351',
          severity: 'Critical',
          cvss_score: 9.1,
          type: 'XXE',
          description: 'XML External Entity injection in SAML response processing',
          affected_versions: ['< 1.3.0'],
          test_endpoints: ['/auth/saml/callback']
        }
      ],
      'discourse-data-explorer' => [
        {
          cve: 'CVE-2023-12352',
          severity: 'Critical',
          cvss_score: 9.9,
          type: 'SQL Injection',
          description: 'Arbitrary SQL execution through data explorer queries',
          affected_versions: ['< 0.3.0'],
          test_endpoints: ['/admin/plugins/explorer']
        }
      ],
      'discourse-chat' => [
        {
          cve: 'CVE-2023-45131',
          severity: 'High',
          cvss_score: 8.2,
          type: 'Unauthorized Access',
          description: 'Unauthenticated chat access vulnerability',
          affected_versions: ['< 1.2.0'],
          test_endpoints: ['/chat', '/chat/api']
        }
      ]
    }.freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
    end
    
    def scan
      results = {
        module_name: 'Plugin Scanner',
        target_url: @target_url,
        scan_time: Time.current,
        detected_plugins: [],
        plugin_vulnerabilities: [],
        outdated_plugins: [],
        high_risk_plugins: [],
        plugin_endpoints: [],
        summary: {
          total_plugins: 0,
          vulnerable_plugins: 0,
          high_risk_plugins: 0,
          total_vulnerabilities: 0
        }
      }
      
      begin
        # Perform plugin detection
        detected_plugins = detect_plugins
        results[:detected_plugins] = detected_plugins
        
        # Vulnerability check for each detected plugin
        detected_plugins.each do |plugin|
          plugin_name = plugin[:name]
          
          # Check plugin vulnerabilities
          vulnerabilities = check_plugin_vulnerabilities(plugin_name, plugin)
          results[:plugin_vulnerabilities].concat(vulnerabilities)
          
          # High-risk plugin check
          if is_high_risk_plugin?(plugin_name)
            results[:high_risk_plugins] << plugin
          end
          
          # Discover plugin endpoints
          endpoints = discover_plugin_endpoints(plugin_name)
          results[:plugin_endpoints].concat(endpoints)
        end
        
        # Calculate summary information
        results[:summary] = calculate_summary(results)
        
      rescue => e
        Rails.logger.error "[PluginScanner] Error: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def detect_plugins
      detected_plugins = []
      
      # Admin plugins API'sini dene
      admin_plugins = detect_plugins_via_admin_api
      detected_plugins.concat(admin_plugins)
      
      # Plugin detection via asset analysis
      asset_plugins = detect_plugins_via_assets
      detected_plugins.concat(asset_plugins)
      
      # Plugin detection via JavaScript analysis
      js_plugins = detect_plugins_via_javascript
      detected_plugins.concat(js_plugins)
      
      # Plugin detection via HTML content analysis
      html_plugins = detect_plugins_via_html_content
      detected_plugins.concat(html_plugins)
      
      # Plugin detection via endpoint analysis
      endpoint_plugins = detect_plugins_via_endpoints
      detected_plugins.concat(endpoint_plugins)
      
      # Remove duplicates
      detected_plugins.uniq { |p| p[:name] }
    end
    
    def detect_plugins_via_admin_api
      plugins = []
      
      begin
        response = make_request('GET', "#{@target_url}/admin/plugins.json")
        if response&.success?
          plugin_data = JSON.parse(response.body)
          if plugin_data['plugins']
            plugin_data['plugins'].each do |plugin|
              plugins << {
                name: plugin['name'],
                version: plugin['version'],
                enabled: plugin['enabled'],
                detection_method: 'admin_api',
                confidence: 100
              }
            end
          end
        end
      rescue => e
        Rails.logger.debug "[PluginScanner] Admin API access error: #{e.message}"
      end
      
      plugins
    end
    
    def detect_plugins_via_assets
      plugins = []
      
      begin
        response = make_request('GET', @target_url)
        return plugins unless response&.success?
        
        # Plugin detection from asset URLs
        asset_matches = response.body.scan(/\/assets\/plugins\/([\w-]+)/)
        asset_matches.each do |match|
          plugin_name = match[0]
          
          plugins << {
            name: plugin_name,
            version: 'Unknown',
            detection_method: 'asset_analysis',
            confidence: 80
          }
        end
        
        # Check known plugin signatures
        KNOWN_PLUGINS.each do |plugin_name, plugin_info|
          plugin_info[:signatures].each do |signature|
            if response.body.include?(signature)
              plugins << {
                name: plugin_name,
                version: 'Unknown',
                detection_method: 'signature_match',
                confidence: 90,
                signature: signature,
                category: plugin_info[:category],
                risk_level: plugin_info[:risk_level],
                description: plugin_info[:description]
              }
              break
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[PluginScanner] Asset analysis error: #{e.message}"
      end
      
      plugins
    end
    
    def detect_plugins_via_javascript
      plugins = []
      
      begin
        response = make_request('GET', @target_url)
        return plugins unless response&.success?
        
        # Plugin detection from JavaScript files
        js_urls = extract_js_urls(response.body)
        
        js_urls.each do |js_url|
          js_response = make_request('GET', js_url)
          next unless js_response&.success?
          
          # Plugin-specific JavaScript patterns
          plugin_patterns = {
            'discourse-chat' => ['Discourse.Chat', 'chatEnabled'],
            'discourse-polls' => ['Discourse.Poll', 'pollsEnabled'],
            'discourse-calendar' => ['Discourse.Calendar', 'calendarEnabled'],
            'discourse-solved' => ['Discourse.Solved', 'solvedEnabled']
          }
          
          plugin_patterns.each do |plugin_name, patterns|
            patterns.each do |pattern|
              if js_response.body.include?(pattern)
                plugins << {
                  name: plugin_name,
                  version: extract_version_from_js(js_response.body, plugin_name),
                  detection_method: 'javascript_analysis',
                  confidence: 85,
                  pattern: pattern
                }
                break
              end
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[PluginScanner] JavaScript analysis error: #{e.message}"
      end
      
      plugins
    end
    
    def detect_plugins_via_html_content
      plugins = []
      
      begin
        response = make_request('GET', @target_url)
        return plugins unless response&.success?
        
        # Plugin detection from HTML meta tags
        meta_patterns = {
          'discourse-chat' => ['data-chat-enabled', 'chat-container'],
          'discourse-polls' => ['data-poll-enabled', 'poll-container'],
          'discourse-calendar' => ['data-calendar-enabled', 'calendar-widget']
        }
        
        meta_patterns.each do |plugin_name, patterns|
          patterns.each do |pattern|
            if response.body.include?(pattern)
              plugins << {
                name: plugin_name,
                version: 'Unknown',
                detection_method: 'html_analysis',
                confidence: 75,
                pattern: pattern
              }
              break
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[PluginScanner] HTML analysis error: #{e.message}"
      end
      
      plugins
    end
    
    def detect_plugins_via_endpoints
      plugins = []
      
      # Test known plugin endpoints
      plugin_endpoints = {
        'discourse-chat' => ['/chat', '/chat/api'],
        'discourse-data-explorer' => ['/admin/plugins/explorer'],
        'discourse-oauth2-basic' => ['/auth/oauth2_basic'],
        'discourse-saml' => ['/auth/saml'],
        'discourse-github' => ['/auth/github'],
        'discourse-google-oauth2' => ['/auth/google_oauth2']
      }
      
      plugin_endpoints.each do |plugin_name, endpoints|
        endpoints.each do |endpoint|
          begin
            response = make_request('GET', "#{@target_url}#{endpoint}")
            
            # Responses like 200, 302, 401, 403 may indicate the plugin exists
            if response && [200, 302, 401, 403].include?(response.code.to_i)
              plugins << {
                name: plugin_name,
                version: 'Unknown',
                detection_method: 'endpoint_probe',
                confidence: 70,
                endpoint: endpoint,
                status_code: response.code
              }
              break
            end
          rescue => e
            # Endpoint access error, continue
          end
        end
      end
      
      plugins
    end
    
    def check_plugin_vulnerabilities(plugin_name, plugin_info)
      vulnerabilities = []
      
      plugin_vulns = PLUGIN_VULNERABILITIES[plugin_name]
      return vulnerabilities unless plugin_vulns
      
      plugin_vulns.each do |vuln|
        # Version check (if version information is available)
        if plugin_info[:version] && plugin_info[:version] != 'Unknown'
          next unless version_affected?(plugin_info[:version], vuln[:affected_versions])
        end
        
        vulnerability = {
          plugin_name: plugin_name,
          cve: vuln[:cve],
          severity: vuln[:severity],
          cvss_score: vuln[:cvss_score],
          type: vuln[:type],
          description: vuln[:description],
          affected_versions: vuln[:affected_versions],
          test_result: test_plugin_vulnerability(vuln)
        }
        
        vulnerabilities << vulnerability
      end
      
      vulnerabilities
    end
    
    def test_plugin_vulnerability(vuln_info)
      return { tested: false } unless vuln_info[:test_endpoints]
      
      results = []
      
      vuln_info[:test_endpoints].each do |endpoint|
        begin
          response = make_request('GET', "#{@target_url}#{endpoint}")
          results << {
            endpoint: endpoint,
            status_code: response&.code,
            accessible: response && [200, 302].include?(response.code.to_i),
            tested: true
          }
        rescue => e
          results << {
            endpoint: endpoint,
            error: e.message,
            tested: false
          }
        end
      end
      
      { tested: true, results: results }
    end
    
    def discover_plugin_endpoints(plugin_name)
      endpoints = []
      
      # Plugin-specific endpoint discovery
      case plugin_name
      when 'discourse-chat'
        chat_endpoints = ['/chat', '/chat/api', '/chat/channels']
        chat_endpoints.each { |ep| endpoints << { plugin: plugin_name, endpoint: ep } }
      when 'discourse-data-explorer'
        explorer_endpoints = ['/admin/plugins/explorer', '/admin/plugins/explorer/queries']
        explorer_endpoints.each { |ep| endpoints << { plugin: plugin_name, endpoint: ep } }
      when /discourse-.*auth/
        auth_endpoints = ["/auth/#{plugin_name.gsub('discourse-', '').gsub('-auth', '')}"]
        auth_endpoints.each { |ep| endpoints << { plugin: plugin_name, endpoint: ep } }
      end
      
      endpoints
    end
    
    def is_high_risk_plugin?(plugin_name)
      high_risk_plugins = [
        'discourse-data-explorer',  # SQL execution capability
        'discourse-oauth2-basic',   # Authentication bypass risks
        'discourse-saml',          # XXE and auth bypass risks
        'discourse-ldap-auth'      # LDAP injection risks
      ]
      
      high_risk_plugins.include?(plugin_name)
    end
    
    def extract_js_urls(html_content)
      urls = []
      
      # Extract URLs from script tags
      script_matches = html_content.scan(/<script[^>]+src=["']([^"']+)["']/i)
      script_matches.each do |match|
        url = match[0]
        url = "#{@target_url}#{url}" if url.start_with?('/')
        urls << url
      end
      
      urls
    end
    
    def extract_version_from_js(js_content, plugin_name)
      # Try to extract version information from JavaScript content
      version_patterns = [
        /#{plugin_name}["']?\s*:\s*["']([\d\.]+)["']/i,
        /version["']?\s*:\s*["']([\d\.]+)["']/i,
        /v([\d\.]+)/i
      ]
      
      version_patterns.each do |pattern|
        match = js_content.match(pattern)
        return match[1] if match
      end
      
      'Unknown'
    end
    
    def version_affected?(current_version, affected_versions)
      return false unless current_version && affected_versions
      
      affected_versions.any? do |version_range|
        if version_range.start_with?('< ')
          target_version = version_range[2..-1]
          Gem::Version.new(current_version) < Gem::Version.new(target_version)
        elsif version_range.start_with?('> ')
          target_version = version_range[2..-1]
          Gem::Version.new(current_version) > Gem::Version.new(target_version)
        else
          current_version == version_range
        end
      end
    rescue
      false
    end
    
    def calculate_summary(results)
      {
        total_plugins: results[:detected_plugins].length,
        vulnerable_plugins: results[:plugin_vulnerabilities].map { |v| v[:plugin_name] }.uniq.length,
        high_risk_plugins: results[:high_risk_plugins].length,
        total_vulnerabilities: results[:plugin_vulnerabilities].length
      }
    end
    
    def make_request(method, url, options = {})
      begin
        case method.upcase
        when 'GET'
          Net::HTTP.get_response(URI(url))
        when 'HEAD'
          uri = URI(url)
          Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
            http.head(uri.path)
          end
        when 'POST'
          uri = URI(url)
          Net::HTTP.post_form(uri, options[:data] || {})
        end
      rescue => e
        Rails.logger.error "[PluginScanner] HTTP request error: #{e.message}"
        nil
      end
    end
  end
end