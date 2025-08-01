# frozen_string_literal: true

module DiscourseMap
  class UserScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Common usernames
    COMMON_USERNAMES = [
      'admin', 'administrator', 'root', 'user', 'test', 'demo',
      'guest', 'moderator', 'mod', 'support', 'help', 'info',
      'contact', 'webmaster', 'postmaster', 'hostmaster',
      'discourse', 'system', 'bot', 'api', 'service',
      'staff', 'team', 'owner', 'founder', 'ceo', 'manager'
    ].freeze
    
    # Discourse-specific roles
    DISCOURSE_ROLES = [
      'admin', 'moderator', 'staff', 'trust_level_4',
      'trust_level_3', 'trust_level_2', 'trust_level_1',
      'trust_level_0', 'suspended', 'silenced'
    ].freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
    end
    
    def scan
      results = {
        module_name: 'User Scanner',
        target_url: @target_url,
        scan_time: Time.current,
        discovered_users: [],
        admin_users: [],
        moderator_users: [],
        high_privilege_users: [],
        user_enumeration_methods: [],
        user_statistics: {},
        security_issues: [],
        summary: {
          total_users: 0,
          admin_users: 0,
          moderator_users: 0,
          enumeration_methods: 0,
          security_issues: 0
        }
      }
      
      begin
        # Test user enumeration methods
        enumeration_methods = test_user_enumeration_methods
        results[:user_enumeration_methods] = enumeration_methods
        
        # Discover users
        discovered_users = discover_users
        results[:discovered_users] = discovered_users
        
        # Identify admin and moderator users
        admin_users = identify_admin_users(discovered_users)
        results[:admin_users] = admin_users
        
        moderator_users = identify_moderator_users(discovered_users)
        results[:moderator_users] = moderator_users
        
        # Identify high privilege users
        high_privilege_users = identify_high_privilege_users(discovered_users)
        results[:high_privilege_users] = high_privilege_users
        
        # Gather user statistics
        user_stats = gather_user_statistics
        results[:user_statistics] = user_stats
        
        # Identify security issues
        security_issues = identify_security_issues(discovered_users)
        results[:security_issues] = security_issues
        
        # Calculate summary information
        results[:summary] = calculate_summary(results)
        
      rescue => e
        Rails.logger.error "[UserScanner] Error: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def test_user_enumeration_methods
      methods = []
      
      # Test API endpoints
      api_methods = test_api_enumeration
      methods.concat(api_methods)
      
      # User profile enumeration
      profile_methods = test_profile_enumeration
      methods.concat(profile_methods)
      
      # Login timing attack
      timing_methods = test_timing_enumeration
      methods.concat(timing_methods)
      
      # Directory listing
      directory_methods = test_directory_enumeration
      methods.concat(directory_methods)
      
      # RSS/JSON feeds
      feed_methods = test_feed_enumeration
      methods.concat(feed_methods)
      
      methods
    end
    
    def test_api_enumeration
      methods = []
      
      # Test Users API endpoints
      api_endpoints = [
        '/users.json',
        '/admin/users.json',
        '/users/search.json',
        '/directory_items.json',
        '/groups.json',
        '/about.json'
      ]
      
      api_endpoints.each do |endpoint|
        begin
          response = make_request('GET', "#{@target_url}#{endpoint}")
          
          if response&.success?
            users_found = extract_users_from_api_response(response.body, endpoint)
            
            methods << {
              method: 'api_enumeration',
              endpoint: endpoint,
              status: 'accessible',
              users_found: users_found.length,
              users: users_found,
              risk_level: get_api_risk_level(endpoint)
            }
          elsif response&.code == '403'
            methods << {
              method: 'api_enumeration',
              endpoint: endpoint,
              status: 'forbidden',
              risk_level: 'low'
            }
          end
        rescue => e
          # Endpoint access error
        end
      end
      
      methods
    end
    
    def test_profile_enumeration
      methods = []
      
      # Test common usernames
      COMMON_USERNAMES.each do |username|
        begin
          response = make_request('GET', "#{@target_url}/u/#{username}")
          
          if response&.success?
            user_info = extract_user_info_from_profile(response.body, username)
            
            methods << {
              method: 'profile_enumeration',
              username: username,
              status: 'exists',
              user_info: user_info,
              risk_level: 'medium'
            }
          end
        rescue => e
          # Profile access error
        end
        
        # Short wait for rate limiting
        sleep(0.1) if @options[:respect_rate_limit]
      end
      
      methods
    end
    
    def test_timing_enumeration
      methods = []
      
      begin
        # Test timing attack with existing and non-existing usernames
        existing_user = 'admin'
        non_existing_user = 'nonexistentuser12345'
        
        # Timing for existing user
        start_time = Time.current
        response1 = make_request('POST', "#{@target_url}/session", {
          data: { login: existing_user, password: 'wrongpassword' }
        })
        existing_time = Time.current - start_time
        
        sleep(1)
        
        # Timing for non-existing user
        start_time = Time.current
        response2 = make_request('POST', "#{@target_url}/session", {
          data: { login: non_existing_user, password: 'wrongpassword' }
        })
        non_existing_time = Time.current - start_time
        
        # Analyze timing difference
        time_difference = (existing_time - non_existing_time).abs
        
        if time_difference > 0.5  # More than 500ms difference
          methods << {
            method: 'timing_attack',
            status: 'vulnerable',
            existing_user_time: existing_time,
            non_existing_user_time: non_existing_time,
            time_difference: time_difference,
            risk_level: 'high'
          }
        end
        
      rescue => e
        # Timing attack test error
      end
      
      methods
    end
    
    def test_directory_enumeration
      methods = []
      
      # Test directory listing endpoints
      directory_endpoints = [
        '/users/',
        '/u/',
        '/admin/users/',
        '/directory/',
        '/groups/'
      ]
      
      directory_endpoints.each do |endpoint|
        begin
          response = make_request('GET', "#{@target_url}#{endpoint}")
          
          if response&.success? && response.body.include?('Index of')
            methods << {
              method: 'directory_listing',
              endpoint: endpoint,
              status: 'accessible',
              risk_level: 'high'
            }
          end
        rescue => e
          # Directory listing test error
        end
      end
      
      methods
    end
    
    def test_feed_enumeration
      methods = []
      
      # Test RSS and JSON feeds
      feed_endpoints = [
        '/latest.rss',
        '/latest.json',
        '/top.json',
        '/users.rss',
        '/directory_items.rss'
      ]
      
      feed_endpoints.each do |endpoint|
        begin
          response = make_request('GET', "#{@target_url}#{endpoint}")
          
          if response&.success?
            users_found = extract_users_from_feed(response.body, endpoint)
            
            methods << {
              method: 'feed_enumeration',
              endpoint: endpoint,
              status: 'accessible',
              users_found: users_found.length,
              users: users_found,
              risk_level: 'medium'
            }
          end
        rescue => e
          # Feed enumeration test error
        end
      end
      
      methods
    end
    
    def discover_users
      users = []
      
      # Collect users from API
      api_users = discover_users_via_api
      users.concat(api_users)
      
      # Collect users from profile enumeration
      profile_users = discover_users_via_profiles
      users.concat(profile_users)
      
      # Collect users from feeds
      feed_users = discover_users_via_feeds
      users.concat(feed_users)
      
      # Collect users from about page
      about_users = discover_users_via_about_page
      users.concat(about_users)
      
      # Remove duplicates
      users.uniq { |u| u[:username] }
    end
    
    def discover_users_via_api
      users = []
      
      begin
        # Users API
        response = make_request('GET', "#{@target_url}/users.json")
        if response&.success?
          api_users = extract_users_from_api_response(response.body, '/users.json')
          users.concat(api_users)
        end
        
        # Directory API
        response = make_request('GET', "#{@target_url}/directory_items.json")
        if response&.success?
          directory_users = extract_users_from_api_response(response.body, '/directory_items.json')
          users.concat(directory_users)
        end
        
        # Groups API (to get group members)
        response = make_request('GET', "#{@target_url}/groups.json")
        if response&.success?
          group_data = JSON.parse(response.body)
          if group_data['groups']
            group_data['groups'].each do |group|
              group_response = make_request('GET', "#{@target_url}/groups/#{group['name']}/members.json")
              if group_response&.success?
                group_users = extract_users_from_api_response(group_response.body, "/groups/#{group['name']}/members.json")
                users.concat(group_users)
              end
            end
          end
        end
        
      rescue => e
        Rails.logger.error "[UserScanner] API user discovery error: #{e.message}"
      end
      
      users
    end
    
    def discover_users_via_profiles
      users = []
      
      COMMON_USERNAMES.each do |username|
        begin
          response = make_request('GET', "#{@target_url}/u/#{username}")
          
          if response&.success?
            user_info = extract_user_info_from_profile(response.body, username)
            users << user_info if user_info
          end
        rescue => e
          # Profile access error
        end
        
        sleep(0.1) if @options[:respect_rate_limit]
      end
      
      users
    end
    
    def discover_users_via_feeds
      users = []
      
      feed_endpoints = ['/latest.json', '/top.json']
      
      feed_endpoints.each do |endpoint|
        begin
          response = make_request('GET', "#{@target_url}#{endpoint}")
          if response&.success?
            feed_users = extract_users_from_feed(response.body, endpoint)
            users.concat(feed_users)
          end
        rescue => e
          # Feed access error
        end
      end
      
      users
    end
    
    def discover_users_via_about_page
      users = []
      
      begin
        response = make_request('GET', "#{@target_url}/about.json")
        if response&.success?
          about_data = JSON.parse(response.body)
          
          # Check moderator and admin lists
          if about_data['about'] && about_data['about']['moderators']
            about_data['about']['moderators'].each do |mod|
              users << {
                username: mod['username'],
                name: mod['name'],
                role: 'moderator',
                discovery_method: 'about_page',
                avatar_url: mod['avatar_template']
              }
            end
          end
          
          if about_data['about'] && about_data['about']['admins']
            about_data['about']['admins'].each do |admin|
              users << {
                username: admin['username'],
                name: admin['name'],
                role: 'admin',
                discovery_method: 'about_page',
                avatar_url: admin['avatar_template']
              }
            end
          end
        end
      rescue => e
        Rails.logger.error "[UserScanner] About page user discovery error: #{e.message}"
      end
      
      users
    end
    
    def identify_admin_users(users)
      admin_users = users.select do |user|
        user[:role] == 'admin' || 
        user[:trust_level] == 4 ||
        user[:admin] == true ||
        COMMON_USERNAMES.include?(user[:username]&.downcase)
      end
      
      admin_users
    end
    
    def identify_moderator_users(users)
      moderator_users = users.select do |user|
        user[:role] == 'moderator' ||
        user[:moderator] == true
      end
      
      moderator_users
    end
    
    def identify_high_privilege_users(users)
      high_privilege_users = users.select do |user|
        user[:role] == 'admin' ||
        user[:role] == 'moderator' ||
        user[:trust_level] && user[:trust_level] >= 3
      end
      
      high_privilege_users
    end
    
    def gather_user_statistics
      stats = {}
      
      begin
        response = make_request('GET', "#{@target_url}/about.json")
        if response&.success?
          about_data = JSON.parse(response.body)
          
          if about_data['about'] && about_data['about']['stats']
            stats = {
              total_users: about_data['about']['stats']['users_count'],
              active_users: about_data['about']['stats']['active_users'],
              posts_count: about_data['about']['stats']['posts_count'],
              topics_count: about_data['about']['stats']['topics_count']
            }
          end
        end
      rescue => e
        Rails.logger.error "[UserScanner] Statistics gathering error: #{e.message}"
      end
      
      stats
    end
    
    def identify_security_issues(users)
      issues = []
      
      # Default admin username check
      default_admins = users.select { |u| ['admin', 'administrator'].include?(u[:username]&.downcase) }
      if default_admins.any?
        issues << {
          type: 'default_admin_username',
          severity: 'High',
          description: 'Default admin username detected',
          users: default_admins,
          recommendation: 'Change default admin usernames'
        }
      end
      
      # Too many admin users
      admin_count = users.count { |u| u[:role] == 'admin' }
      if admin_count > 5
        issues << {
          type: 'excessive_admin_users',
          severity: 'Medium',
          description: "Too many admin users detected (#{admin_count})",
          recommendation: 'Review admin user privileges'
        }
      end
      
      # User enumeration vulnerability
      if test_user_enumeration_vulnerability
        issues << {
          type: 'user_enumeration_vulnerability',
          severity: 'Medium',
          description: 'User enumeration vulnerability detected',
          recommendation: 'Implement rate limiting and consistent responses'
        }
      end
      
      issues
    end
    
    def test_user_enumeration_vulnerability
      # Simple user enumeration test
      begin
        response1 = make_request('GET', "#{@target_url}/u/admin")
        response2 = make_request('GET', "#{@target_url}/u/nonexistentuser12345")
        
        # Different responses may indicate user enumeration
        return response1&.code != response2&.code
      rescue
        false
      end
    end
    
    def extract_users_from_api_response(response_body, endpoint)
      users = []
      
      begin
        data = JSON.parse(response_body)
        
        case endpoint
        when '/users.json'
          if data['directory_items']
            data['directory_items'].each do |item|
              users << extract_user_from_directory_item(item)
            end
          end
        when '/directory_items.json'
          if data['directory_items']
            data['directory_items'].each do |item|
              users << extract_user_from_directory_item(item)
            end
          end
        when /\/groups\/.*\/members\.json/
          if data['members']
            data['members'].each do |member|
              users << {
                username: member['username'],
                name: member['name'],
                discovery_method: 'group_members_api',
                avatar_url: member['avatar_template']
              }
            end
          end
        end
      rescue JSON::ParserError => e
        Rails.logger.error "[UserScanner] JSON parse error: #{e.message}"
      end
      
      users.compact
    end
    
    def extract_user_from_directory_item(item)
      return nil unless item['user']
      
      user = item['user']
      {
        username: user['username'],
        name: user['name'],
        trust_level: user['trust_level'],
        admin: user['admin'],
        moderator: user['moderator'],
        discovery_method: 'directory_api',
        avatar_url: user['avatar_template'],
        last_seen: user['last_seen_at']
      }
    end
    
    def extract_user_info_from_profile(html_content, username)
      # Extract user information from HTML
      user_info = {
        username: username,
        discovery_method: 'profile_page'
      }
      
      # Trust level
      trust_match = html_content.match(/trust[_-]?level["']?\s*:?\s*["']?(\d+)/i)
      user_info[:trust_level] = trust_match[1].to_i if trust_match
      
      # Admin/Moderator badge
      if html_content.match(/admin|administrator/i)
        user_info[:role] = 'admin'
      elsif html_content.match(/moderator|mod/i)
        user_info[:role] = 'moderator'
      end
      
      # Name
      name_match = html_content.match(/<h1[^>]*>([^<]+)<\/h1>/i)
      user_info[:name] = name_match[1].strip if name_match
      
      user_info
    end
    
    def extract_users_from_feed(response_body, endpoint)
      users = []
      
      begin
        if endpoint.end_with?('.json')
          data = JSON.parse(response_body)
          
          if data['users']
            data['users'].each do |user|
              users << {
                username: user['username'],
                name: user['name'],
                discovery_method: 'json_feed',
                avatar_url: user['avatar_template']
              }
            end
          end
          
          # Extract users from topic lists
          if data['topic_list'] && data['topic_list']['topics']
            data['topic_list']['topics'].each do |topic|
              if topic['posters']
                topic['posters'].each do |poster|
                  users << {
                    username: poster['user']['username'],
                    discovery_method: 'topic_feed'
                  }
                end
              end
            end
          end
        end
      rescue JSON::ParserError => e
        Rails.logger.error "[UserScanner] Feed JSON parse error: #{e.message}"
      end
      
      users.compact
    end
    
    def get_api_risk_level(endpoint)
      case endpoint
      when '/admin/users.json'
        'critical'
      when '/users.json', '/directory_items.json'
        'high'
      when '/groups.json'
        'medium'
      else
        'low'
      end
    end
    
    def calculate_summary(results)
      {
        total_users: results[:discovered_users].length,
        admin_users: results[:admin_users].length,
        moderator_users: results[:moderator_users].length,
        enumeration_methods: results[:user_enumeration_methods].length,
        security_issues: results[:security_issues].length
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
        Rails.logger.error "[UserScanner] HTTP request error: #{e.message}"
        nil
      end
    end
  end
end