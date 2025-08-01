# frozen_string_literal: true

module DiscourseMap
  class ThemeScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Known Discourse themes and signatures
    KNOWN_THEMES = {
      'default' => {
        signatures: [
          'discourse-default-theme',
          'theme-default'
        ],
        category: 'official',
        risk_level: 'low',
        description: 'Default Discourse Theme'
      },
      'graceful' => {
        signatures: [
          'graceful-theme',
          'theme-graceful'
        ],
        category: 'community',
        risk_level: 'medium',
        description: 'Graceful Community Theme'
      },
      'material-design' => {
        signatures: [
          'material-design-theme',
          'theme-material'
        ],
        category: 'community',
        risk_level: 'medium',
        description: 'Material Design Theme'
      },
      'dark-light-toggle' => {
        signatures: [
          'dark-light-toggle',
          'theme-toggle'
        ],
        category: 'utility',
        risk_level: 'low',
        description: 'Dark/Light Mode Toggle Theme'
      },
      'custom-header-links' => {
        signatures: [
          'custom-header-links',
          'header-links-theme'
        ],
        category: 'navigation',
        risk_level: 'medium',
        description: 'Custom Header Links Theme'
      },
      'brand-header' => {
        signatures: [
          'brand-header-theme',
          'branded-header'
        ],
        category: 'branding',
        risk_level: 'low',
        description: 'Branded Header Theme'
      },
      'sidebar-theme' => {
        signatures: [
          'sidebar-theme',
          'custom-sidebar'
        ],
        category: 'layout',
        risk_level: 'medium',
        description: 'Custom Sidebar Theme'
      },
      'discourse-kanban-theme' => {
        signatures: [
          'kanban-theme',
          'discourse-kanban'
        ],
        category: 'productivity',
        risk_level: 'medium',
        description: 'Kanban Board Theme'
      },
      'discourse-gated-theme' => {
        signatures: [
          'gated-theme',
          'discourse-gated'
        ],
        category: 'access-control',
        risk_level: 'high',
        description: 'Gated Access Theme'
      },
      'custom-wizard-theme' => {
        signatures: [
          'custom-wizard',
          'wizard-theme'
        ],
        category: 'workflow',
        risk_level: 'high',
        description: 'Custom Wizard Theme'
      }
    }.freeze
    
    # Theme vulnerabilities database
    THEME_VULNERABILITIES = {
      'custom-header-links' => [
        {
          cve: 'CVE-2023-12360',
          severity: 'Medium',
          cvss_score: 6.1,
          type: 'XSS',
          description: 'Cross-site scripting in custom header links',
          affected_versions: ['< 1.2.0'],
          test_patterns: ['<script>', 'javascript:', 'onload=']
        }
      ],
      'discourse-gated-theme' => [
        {
          cve: 'CVE-2023-12361',
          severity: 'High',
          cvss_score: 8.1,
          type: 'Access Control Bypass',
          description: 'Authentication bypass in gated theme',
          affected_versions: ['< 2.1.0'],
          test_endpoints: ['/gated', '/private']
        }
      ],
      'custom-wizard-theme' => [
        {
          cve: 'CVE-2023-12362',
          severity: 'Critical',
          cvss_score: 9.3,
          type: 'Code Injection',
          description: 'Server-side template injection in wizard forms',
          affected_versions: ['< 1.5.0'],
          test_patterns: ['{{', '<%', '${', '#{']
        }
      ]
    }.freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
    end
    
    def scan
      results = {
        module_name: 'Theme Scanner',
        target_url: @target_url,
        scan_time: Time.current,
        detected_themes: [],
        theme_vulnerabilities: [],
        outdated_themes: [],
        high_risk_themes: [],
        custom_css_issues: [],
        theme_components: [],
        summary: {
          total_themes: 0,
          vulnerable_themes: 0,
          high_risk_themes: 0,
          total_vulnerabilities: 0,
          css_issues: 0
        }
      }
      
      begin
        # Perform theme detection
        detected_themes = detect_themes
        results[:detected_themes] = detected_themes
        
        # Check vulnerabilities for each detected theme
        detected_themes.each do |theme|
          theme_name = theme[:name]
          
          # Check theme vulnerabilities
          vulnerabilities = check_theme_vulnerabilities(theme_name, theme)
          results[:theme_vulnerabilities].concat(vulnerabilities)
          
          # High-risk theme check
          if is_high_risk_theme?(theme_name)
            results[:high_risk_themes] << theme
          end
        end
        
        # CSS security analysis
        css_issues = analyze_custom_css
        results[:custom_css_issues] = css_issues
        
        # Detect theme components
        theme_components = detect_theme_components
        results[:theme_components] = theme_components
        
        # Calculate summary information
        results[:summary] = calculate_summary(results)
        
      rescue => e
        Rails.logger.error "[ThemeScanner] Error: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def detect_themes
      detected_themes = []
      
      # Try admin themes API
      admin_themes = detect_themes_via_admin_api
      detected_themes.concat(admin_themes)
      
      # Theme detection via CSS analysis
      css_themes = detect_themes_via_css_analysis
      detected_themes.concat(css_themes)
      
      # Theme detection via HTML class analysis
      html_themes = detect_themes_via_html_classes
      detected_themes.concat(html_themes)
      
      # Theme detection via JavaScript analysis
      js_themes = detect_themes_via_javascript
      detected_themes.concat(js_themes)
      
      # Theme detection via meta tag analysis
      meta_themes = detect_themes_via_meta_tags
      detected_themes.concat(meta_themes)
      
      # Remove duplicates
      detected_themes.uniq { |t| t[:name] }
    end
    
    def detect_themes_via_admin_api
      themes = []
      
      begin
        response = make_request('GET', "#{@target_url}/admin/themes.json")
        if response&.success?
          theme_data = JSON.parse(response.body)
          if theme_data['themes']
            theme_data['themes'].each do |theme|
              themes << {
                name: theme['name'],
                id: theme['id'],
                default: theme['default'],
                user_selectable: theme['user_selectable'],
                detection_method: 'admin_api',
                confidence: 100
              }
            end
          end
        end
      rescue => e
        Rails.logger.debug "[ThemeScanner] Admin API access error: #{e.message}"
      end
      
      themes
    end
    
    def detect_themes_via_css_analysis
      themes = []
      
      begin
        response = make_request('GET', @target_url)
        return themes unless response&.success?
        
        # Extract CSS file URLs
        css_urls = extract_css_urls(response.body)
        
        css_urls.each do |css_url|
          css_response = make_request('GET', css_url)
          next unless css_response&.success?
          
          # Check known theme signatures
          KNOWN_THEMES.each do |theme_name, theme_info|
            theme_info[:signatures].each do |signature|
              if css_response.body.include?(signature)
                themes << {
                  name: theme_name,
                  detection_method: 'css_analysis',
                  confidence: 85,
                  signature: signature,
                  css_url: css_url,
                  category: theme_info[:category],
                  risk_level: theme_info[:risk_level],
                  description: theme_info[:description]
                }
                break
              end
            end
          end
          
          # Check custom theme patterns
          custom_patterns = [
            'custom-theme',
            'discourse-custom',
            'theme-component',
            'custom-css'
          ]
          
          custom_patterns.each do |pattern|
            if css_response.body.include?(pattern)
              themes << {
                name: 'custom-theme',
                detection_method: 'css_pattern_match',
                confidence: 70,
                pattern: pattern,
                css_url: css_url
              }
              break
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[ThemeScanner] CSS analysis error: #{e.message}"
      end
      
      themes
    end
    
    def detect_themes_via_html_classes
      themes = []
      
      begin
        response = make_request('GET', @target_url)
        return themes unless response&.success?
        
        # Theme detection from HTML body classes
        body_class_match = response.body.match(/<body[^>]+class=["']([^"']+)["']/i)
        if body_class_match
          body_classes = body_class_match[1].split(/\s+/)
          
          # Theme-specific class patterns
          theme_class_patterns = {
            'graceful' => ['graceful-theme', 'theme-graceful'],
            'material-design' => ['material-theme', 'md-theme'],
            'dark-light-toggle' => ['dark-theme', 'light-theme', 'theme-toggle'],
            'brand-header' => ['branded-header', 'custom-header'],
            'sidebar-theme' => ['custom-sidebar', 'sidebar-theme']
          }
          
          theme_class_patterns.each do |theme_name, patterns|
            patterns.each do |pattern|
              if body_classes.any? { |cls| cls.include?(pattern) }
                themes << {
                  name: theme_name,
                  detection_method: 'html_class_analysis',
                  confidence: 80,
                  class_pattern: pattern
                }
                break
              end
            end
          end
        end
        
        # Theme detection from data attributes
        data_theme_match = response.body.match(/data-theme=["']([^"']+)["']/i)
        if data_theme_match
          theme_name = data_theme_match[1]
          themes << {
            name: theme_name,
            detection_method: 'data_attribute',
            confidence: 90,
            data_theme: theme_name
          }
        end
        
      rescue => e
        Rails.logger.error "[ThemeScanner] HTML class analysis error: #{e.message}"
      end
      
      themes
    end
    
    def detect_themes_via_javascript
      themes = []
      
      begin
        response = make_request('GET', @target_url)
        return themes unless response&.success?
        
        # Theme detection from JavaScript files
        js_urls = extract_js_urls(response.body)
        
        js_urls.each do |js_url|
          js_response = make_request('GET', js_url)
          next unless js_response&.success?
          
          # Theme-specific JavaScript patterns
          theme_js_patterns = {
            'dark-light-toggle' => ['toggleTheme', 'darkMode', 'lightMode'],
            'custom-wizard-theme' => ['CustomWizard', 'wizardTheme'],
            'discourse-kanban-theme' => ['KanbanBoard', 'kanbanTheme'],
            'sidebar-theme' => ['customSidebar', 'sidebarTheme']
          }
          
          theme_js_patterns.each do |theme_name, patterns|
            patterns.each do |pattern|
              if js_response.body.include?(pattern)
                themes << {
                  name: theme_name,
                  detection_method: 'javascript_analysis',
                  confidence: 85,
                  js_pattern: pattern,
                  js_url: js_url
                }
                break
              end
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[ThemeScanner] JavaScript analysis error: #{e.message}"
      end
      
      themes
    end
    
    def detect_themes_via_meta_tags
      themes = []
      
      begin
        response = make_request('GET', @target_url)
        return themes unless response&.success?
        
        # Extract theme information from meta tags
        meta_theme_match = response.body.match(/<meta[^>]+name=["']theme["'][^>]+content=["']([^"']+)["']/i)
        if meta_theme_match
          theme_name = meta_theme_match[1]
          themes << {
            name: theme_name,
            detection_method: 'meta_tag',
            confidence: 95,
            meta_content: theme_name
          }
        end
        
        # Theme information from generator meta tag
        generator_match = response.body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*theme[^"']*)["']/i)
        if generator_match
          generator_content = generator_match[1]
          themes << {
            name: 'custom-theme',
            detection_method: 'generator_meta',
            confidence: 70,
            generator: generator_content
          }
        end
        
      rescue => e
        Rails.logger.error "[ThemeScanner] Meta tag analysis error: #{e.message}"
      end
      
      themes
    end
    
    def check_theme_vulnerabilities(theme_name, theme_info)
      vulnerabilities = []
      
      theme_vulns = THEME_VULNERABILITIES[theme_name]
      return vulnerabilities unless theme_vulns
      
      theme_vulns.each do |vuln|
        vulnerability = {
          theme_name: theme_name,
          cve: vuln[:cve],
          severity: vuln[:severity],
          cvss_score: vuln[:cvss_score],
          type: vuln[:type],
          description: vuln[:description],
          affected_versions: vuln[:affected_versions],
          test_result: test_theme_vulnerability(vuln)
        }
        
        vulnerabilities << vulnerability
      end
      
      vulnerabilities
    end
    
    def test_theme_vulnerability(vuln_info)
      results = []
      
      # Pattern-based testing
      if vuln_info[:test_patterns]
        pattern_results = test_vulnerability_patterns(vuln_info[:test_patterns])
        results.concat(pattern_results)
      end
      
      # Endpoint-based testing
      if vuln_info[:test_endpoints]
        endpoint_results = test_vulnerability_endpoints(vuln_info[:test_endpoints])
        results.concat(endpoint_results)
      end
      
      { tested: !results.empty?, results: results }
    end
    
    def test_vulnerability_patterns(patterns)
      results = []
      
      begin
        response = make_request('GET', @target_url)
        return results unless response&.success?
        
        patterns.each do |pattern|
          if response.body.include?(pattern)
            results << {
              type: 'pattern_match',
              pattern: pattern,
              found: true,
              risk: 'potential_vulnerability'
            }
          end
        end
        
      rescue => e
        results << {
          type: 'pattern_test_error',
          error: e.message
        }
      end
      
      results
    end
    
    def test_vulnerability_endpoints(endpoints)
      results = []
      
      endpoints.each do |endpoint|
        begin
          response = make_request('GET', "#{@target_url}#{endpoint}")
          results << {
            type: 'endpoint_test',
            endpoint: endpoint,
            status_code: response&.code,
            accessible: response && [200, 302].include?(response.code.to_i)
          }
        rescue => e
          results << {
            type: 'endpoint_test_error',
            endpoint: endpoint,
            error: e.message
          }
        end
      end
      
      results
    end
    
    def analyze_custom_css
      css_issues = []
      
      begin
        response = make_request('GET', @target_url)
        return css_issues unless response&.success?
        
        css_urls = extract_css_urls(response.body)
        
        css_urls.each do |css_url|
          css_response = make_request('GET', css_url)
          next unless css_response&.success?
          
          # CSS patterns that pose security risks
          risky_patterns = {
            'javascript_in_css' => /javascript:/i,
            'expression_usage' => /expression\s*\(/i,
            'import_external' => /@import\s+url\s*\(\s*["']?https?:\/\//i,
            'behavior_property' => /behavior\s*:/i,
            'binding_property' => /-moz-binding\s*:/i
          }
          
          risky_patterns.each do |issue_type, pattern|
            matches = css_response.body.scan(pattern)
            if matches.any?
              css_issues << {
                type: issue_type,
                css_url: css_url,
                matches_count: matches.length,
                severity: get_css_issue_severity(issue_type),
                description: get_css_issue_description(issue_type)
              }
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[ThemeScanner] CSS analysis error: #{e.message}"
      end
      
      css_issues
    end
    
    def detect_theme_components
      components = []
      
      begin
        response = make_request('GET', @target_url)
        return components unless response&.success?
        
        # Theme component patterns
        component_patterns = {
          'header-component' => ['custom-header', 'theme-header'],
          'footer-component' => ['custom-footer', 'theme-footer'],
          'sidebar-component' => ['custom-sidebar', 'theme-sidebar'],
          'navigation-component' => ['custom-nav', 'theme-navigation'],
          'widget-component' => ['custom-widget', 'theme-widget']
        }
        
        component_patterns.each do |component_type, patterns|
          patterns.each do |pattern|
            if response.body.include?(pattern)
              components << {
                type: component_type,
                pattern: pattern,
                detection_method: 'html_pattern'
              }
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[ThemeScanner] Component detection error: #{e.message}"
      end
      
      components
    end
    
    def is_high_risk_theme?(theme_name)
      high_risk_themes = [
        'discourse-gated-theme',
        'custom-wizard-theme',
        'custom-header-links'
      ]
      
      high_risk_themes.include?(theme_name)
    end
    
    def extract_css_urls(html_content)
      urls = []
      
      # Extract CSS URLs from link tags
      css_matches = html_content.scan(/<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']/i)
      css_matches.each do |match|
        url = match[0]
        url = "#{@target_url}#{url}" if url.start_with?('/')
        urls << url
      end
      
      # Also check style imports
      import_matches = html_content.scan(/@import\s+url\s*\(\s*["']?([^"')]+)["']?\s*\)/i)
      import_matches.each do |match|
        url = match[0]
        url = "#{@target_url}#{url}" if url.start_with?('/')
        urls << url
      end
      
      urls
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
    
    def get_css_issue_severity(issue_type)
      severity_map = {
        'javascript_in_css' => 'High',
        'expression_usage' => 'High',
        'import_external' => 'Medium',
        'behavior_property' => 'Medium',
        'binding_property' => 'Medium'
      }
      
      severity_map[issue_type] || 'Low'
    end
    
    def get_css_issue_description(issue_type)
      description_map = {
        'javascript_in_css' => 'JavaScript code found in CSS (potential XSS)',
        'expression_usage' => 'CSS expression usage (IE-specific security risk)',
        'import_external' => 'External CSS import (potential data leakage)',
        'behavior_property' => 'CSS behavior property (IE-specific security risk)',
        'binding_property' => 'Mozilla binding property (potential code execution)'
      }
      
      description_map[issue_type] || 'Unknown CSS security issue'
    end
    
    def calculate_summary(results)
      {
        total_themes: results[:detected_themes].length,
        vulnerable_themes: results[:theme_vulnerabilities].map { |v| v[:theme_name] }.uniq.length,
        high_risk_themes: results[:high_risk_themes].length,
        total_vulnerabilities: results[:theme_vulnerabilities].length,
        css_issues: results[:custom_css_issues].length
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
        Rails.logger.error "[ThemeScanner] HTTP request error: #{e.message}"
        nil
      end
    end
  end
end