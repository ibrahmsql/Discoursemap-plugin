# frozen_string_literal: true

module DiscourseMap
  class DatabaseScanner
    include ActiveModel::Serialization
    
    attr_accessor :options
    
    # Database security checks
    SECURITY_CHECKS = [
      'check_database_version',
      'check_database_users',
      'check_database_permissions',
      'check_sensitive_data_exposure',
      'check_database_configuration',
      'check_backup_security',
      'check_connection_security',
      'check_audit_logging'
    ].freeze
    
    def initialize(options = {})
      @options = options
    end
    
    def scan
      results = {
        scan_type: 'database_scan',
        timestamp: Time.current,
        database_info: {},
        vulnerabilities: [],
        recommendations: [],
        security_score: 0
      }
      
      Rails.logger.info "[DatabaseScanner] Starting database security scan"
      
      begin
        # Get database information
        get_database_info(results)
        
        # Perform security checks
        SECURITY_CHECKS.each do |check_method|
          send(check_method, results) if respond_to?(check_method, true)
        end
        
        # Calculate security score
        calculate_security_score(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
        Rails.logger.info "[DatabaseScanner] Database scan completed. Security score: #{results[:security_score]}/100"
        
      rescue => e
        Rails.logger.error "[DatabaseScanner] Error during database scan: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def get_database_info(results)
      begin
        connection = ActiveRecord::Base.connection
        
        results[:database_info] = {
          adapter: connection.adapter_name,
          database_name: connection.current_database,
          version: get_database_version(connection),
          encoding: get_database_encoding(connection),
          pool_size: ActiveRecord::Base.connection_pool.size,
          active_connections: ActiveRecord::Base.connection_pool.connections.count
        }
        
      rescue => e
        Rails.logger.error "[DatabaseScanner] Error getting database info: #{e.message}"
        results[:database_info][:error] = e.message
      end
    end
    
    def check_database_version(results)
      begin
        version = results[:database_info][:version]
        adapter = results[:database_info][:adapter]
        
        if version
          # Check for known vulnerable versions
          vulnerable_versions = get_vulnerable_versions(adapter)
          
          vulnerable_versions.each do |vuln_version, details|
            if version_vulnerable?(version, vuln_version)
              vulnerability = {
                type: 'Vulnerable Database Version',
                severity: details[:severity],
                description: "Database version #{version} is vulnerable: #{details[:description]}",
                recommendation: details[:recommendation],
                cve: details[:cve]
              }
              
              results[:vulnerabilities] << vulnerability
            end
          end
          
          # Check if version is outdated
          if version_outdated?(adapter, version)
            vulnerability = {
              type: 'Outdated Database Version',
              severity: 'Medium',
              description: "Database version #{version} is outdated",
              recommendation: 'Update to the latest stable version of the database'
            }
            
            results[:vulnerabilities] << vulnerability
          end
        end
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking database version: #{e.message}"
      end
    end
    
    def check_database_users(results)
      begin
        connection = ActiveRecord::Base.connection
        adapter = results[:database_info][:adapter]
        
        case adapter.downcase
        when 'postgresql'
          check_postgresql_users(results, connection)
        when 'mysql', 'mysql2'
          check_mysql_users(results, connection)
        when 'sqlite3'
          # SQLite doesn't have user management
          results[:database_info][:user_check] = 'SQLite - No user management'
        end
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking database users: #{e.message}"
      end
    end
    
    def check_database_permissions(results)
      begin
        connection = ActiveRecord::Base.connection
        
        # Check if the application user has excessive privileges
        current_user = get_current_database_user(connection)
        
        if current_user
          privileges = get_user_privileges(connection, current_user)
          
          # Check for dangerous privileges
          dangerous_privileges = ['SUPER', 'FILE', 'PROCESS', 'SHUTDOWN', 'CREATE USER', 'GRANT OPTION']
          
          found_dangerous = privileges.select { |priv| dangerous_privileges.include?(priv.upcase) }
          
          if found_dangerous.any?
            vulnerability = {
              type: 'Excessive Database Privileges',
              severity: 'High',
              description: "Database user has dangerous privileges: #{found_dangerous.join(', ')}",
              recommendation: 'Remove unnecessary privileges and follow principle of least privilege'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
          results[:database_info][:current_user] = current_user
          results[:database_info][:privileges] = privileges
        end
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking database permissions: #{e.message}"
      end
    end
    
    def check_sensitive_data_exposure(results)
      begin
        # Check for tables that might contain sensitive data
        sensitive_tables = ['users', 'user_emails', 'user_profiles', 'oauth2_user_infos', 'single_sign_on_records']
        
        sensitive_tables.each do |table_name|
          if table_exists?(table_name)
            # Check if table has proper access controls
            check_table_security(results, table_name)
          end
        end
        
        # Check for unencrypted sensitive columns
        check_encryption_status(results)
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking sensitive data exposure: #{e.message}"
      end
    end
    
    def check_database_configuration(results)
      begin
        connection = ActiveRecord::Base.connection
        adapter = results[:database_info][:adapter]
        
        case adapter.downcase
        when 'postgresql'
          check_postgresql_config(results, connection)
        when 'mysql', 'mysql2'
          check_mysql_config(results, connection)
        end
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking database configuration: #{e.message}"
      end
    end
    
    def check_backup_security(results)
      begin
        # Check if backups are configured
        backup_info = get_backup_configuration
        
        if backup_info[:enabled]
          results[:database_info][:backup_enabled] = true
          
          # Check backup security
          if backup_info[:encryption] == false
            vulnerability = {
              type: 'Unencrypted Database Backups',
              severity: 'High',
              description: 'Database backups are not encrypted',
              recommendation: 'Enable encryption for database backups'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
          if backup_info[:remote_storage] == false
            vulnerability = {
              type: 'Local Backup Storage',
              severity: 'Medium',
              description: 'Backups are stored locally only',
              recommendation: 'Store backups in secure remote location'
            }
            
            results[:vulnerabilities] << vulnerability
          end
        else
          vulnerability = {
            type: 'No Database Backup',
            severity: 'Critical',
            description: 'Database backups are not configured',
            recommendation: 'Configure regular automated database backups'
          }
          
          results[:vulnerabilities] << vulnerability
        end
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking backup security: #{e.message}"
      end
    end
    
    def check_connection_security(results)
      begin
        config = ActiveRecord::Base.connection_config
        
        # Check SSL configuration
        if config[:sslmode].nil? || config[:sslmode] == 'disable'
          vulnerability = {
            type: 'Unencrypted Database Connection',
            severity: 'High',
            description: 'Database connection is not encrypted with SSL/TLS',
            recommendation: 'Enable SSL/TLS encryption for database connections'
          }
          
          results[:vulnerabilities] << vulnerability
        end
        
        # Check for default credentials
        if config[:username] == 'root' || config[:username] == 'admin' || config[:username] == 'postgres'
          vulnerability = {
            type: 'Default Database Credentials',
            severity: 'High',
            description: 'Using default database username',
            recommendation: 'Use a custom database username instead of default ones'
          }
          
          results[:vulnerabilities] << vulnerability
        end
        
        results[:database_info][:connection_config] = {
          host: config[:host],
          port: config[:port],
          username: config[:username],
          ssl_enabled: !config[:sslmode].nil? && config[:sslmode] != 'disable'
        }
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking connection security: #{e.message}"
      end
    end
    
    def check_audit_logging(results)
      begin
        connection = ActiveRecord::Base.connection
        adapter = results[:database_info][:adapter]
        
        case adapter.downcase
        when 'postgresql'
          # Check if logging is enabled
          log_statement = execute_query(connection, "SHOW log_statement")
          
          if log_statement.nil? || log_statement == 'none'
            vulnerability = {
              type: 'Database Audit Logging Disabled',
              severity: 'Medium',
              description: 'Database audit logging is not enabled',
              recommendation: 'Enable database audit logging for security monitoring'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
        when 'mysql', 'mysql2'
          # Check if general log is enabled
          general_log = execute_query(connection, "SHOW VARIABLES LIKE 'general_log'")
          
          if general_log && general_log['Value'] == 'OFF'
            vulnerability = {
              type: 'Database Audit Logging Disabled',
              severity: 'Medium',
              description: 'MySQL general log is disabled',
              recommendation: 'Enable MySQL general log for audit purposes'
            }
            
            results[:vulnerabilities] << vulnerability
          end
        end
        
      rescue => e
        Rails.logger.debug "[DatabaseScanner] Error checking audit logging: #{e.message}"
      end
    end
    
    # Helper methods
    
    def get_database_version(connection)
      begin
        case connection.adapter_name.downcase
        when 'postgresql'
          connection.execute("SELECT version()").first['version']
        when 'mysql', 'mysql2'
          connection.execute("SELECT VERSION()").first.first
        when 'sqlite3'
          connection.execute("SELECT sqlite_version()").first.first
        else
          'Unknown'
        end
      rescue
        'Unknown'
      end
    end
    
    def get_database_encoding(connection)
      begin
        case connection.adapter_name.downcase
        when 'postgresql'
          connection.execute("SHOW server_encoding").first['server_encoding']
        when 'mysql', 'mysql2'
          connection.execute("SELECT @@character_set_database").first.first
        else
          'Unknown'
        end
      rescue
        'Unknown'
      end
    end
    
    def get_vulnerable_versions(adapter)
      case adapter.downcase
      when 'postgresql'
        {
          '< 13.8' => {
            severity: 'High',
            description: 'Multiple security vulnerabilities',
            recommendation: 'Upgrade to PostgreSQL 13.8 or later',
            cve: 'CVE-2022-2625'
          },
          '< 12.12' => {
            severity: 'High',
            description: 'Security vulnerabilities in older versions',
            recommendation: 'Upgrade to PostgreSQL 12.12 or later',
            cve: 'Multiple CVEs'
          }
        }
      when 'mysql', 'mysql2'
        {
          '< 8.0.30' => {
            severity: 'High',
            description: 'Multiple security vulnerabilities',
            recommendation: 'Upgrade to MySQL 8.0.30 or later',
            cve: 'Multiple CVEs'
          },
          '< 5.7.39' => {
            severity: 'Critical',
            description: 'Critical security vulnerabilities',
            recommendation: 'Upgrade to MySQL 5.7.39 or later, or preferably 8.0+',
            cve: 'Multiple CVEs'
          }
        }
      else
        {}
      end
    end
    
    def version_vulnerable?(current_version, vulnerable_version)
      # Simple version comparison - in production, use a proper gem like semantic
      return false unless current_version && vulnerable_version
      
      if vulnerable_version.start_with?('< ')
        target_version = vulnerable_version[2..-1]
        return compare_versions(current_version, target_version) < 0
      end
      
      false
    end
    
    def version_outdated?(adapter, version)
      # Check if version is more than 2 major versions behind
      case adapter.downcase
      when 'postgresql'
        major_version = version.match(/\d+/)&.to_s&.to_i
        return major_version && major_version < 12
      when 'mysql', 'mysql2'
        major_version = version.match(/\d+/)&.to_s&.to_i
        return major_version && major_version < 7
      end
      
      false
    end
    
    def compare_versions(version1, version2)
      # Simple version comparison
      v1_parts = version1.scan(/\d+/).map(&:to_i)
      v2_parts = version2.scan(/\d+/).map(&:to_i)
      
      [v1_parts.length, v2_parts.length].max.times do |i|
        v1_part = v1_parts[i] || 0
        v2_part = v2_parts[i] || 0
        
        return v1_part <=> v2_part if v1_part != v2_part
      end
      
      0
    end
    
    def table_exists?(table_name)
      ActiveRecord::Base.connection.table_exists?(table_name)
    end
    
    def execute_query(connection, query)
      result = connection.execute(query)
      result.first if result.respond_to?(:first)
    rescue
      nil
    end
    
    def get_current_database_user(connection)
      begin
        case connection.adapter_name.downcase
        when 'postgresql'
          connection.execute("SELECT current_user").first['current_user']
        when 'mysql', 'mysql2'
          connection.execute("SELECT USER()").first.first
        else
          'Unknown'
        end
      rescue
        'Unknown'
      end
    end
    
    def get_user_privileges(connection, username)
      # This would need to be implemented based on the specific database
      # For now, return empty array
      []
    end
    
    def check_table_security(results, table_name)
      # Check if sensitive table has proper indexes and constraints
      # This is a placeholder for more detailed table security checks
    end
    
    def check_encryption_status(results)
      # Check if sensitive columns are encrypted
      # This would need to be implemented based on the application's encryption strategy
    end
    
    def check_postgresql_users(results, connection)
      # PostgreSQL specific user checks
    end
    
    def check_mysql_users(results, connection)
      # MySQL specific user checks
    end
    
    def check_postgresql_config(results, connection)
      # PostgreSQL specific configuration checks
    end
    
    def check_mysql_config(results, connection)
      # MySQL specific configuration checks
    end
    
    def get_backup_configuration
      # This would check the actual backup configuration
      # For now, return default values
      {
        enabled: false,
        encryption: false,
        remote_storage: false
      }
    end
    
    def calculate_security_score(results)
      total_checks = SECURITY_CHECKS.length
      failed_checks = results[:vulnerabilities].length
      
      score = ((total_checks - failed_checks).to_f / total_checks * 100).round
      results[:security_score] = [score, 0].max
    end
    
    def generate_recommendations(results)
      recommendations = []
      
      # Group vulnerabilities by type
      vuln_types = results[:vulnerabilities].group_by { |v| v[:type] }
      
      if vuln_types['Vulnerable Database Version']
        recommendations << 'Update database to the latest secure version'
      end
      
      if vuln_types['Excessive Database Privileges']
        recommendations << 'Review and reduce database user privileges'
      end
      
      if vuln_types['Unencrypted Database Connection']
        recommendations << 'Enable SSL/TLS encryption for database connections'
      end
      
      if vuln_types['No Database Backup']
        recommendations << 'Implement automated database backup strategy'
      end
      
      if results[:security_score] < 70
        recommendations << 'Database security configuration needs significant improvement'
      end
      
      results[:recommendations] = recommendations
    end
  end
end