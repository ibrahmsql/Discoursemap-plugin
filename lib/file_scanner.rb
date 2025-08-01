# frozen_string_literal: true

module DiscourseMap
  class FileScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Sensitive files to check for
    SENSITIVE_FILES = [
      # Configuration files
      '.env',
      '.env.local',
      '.env.production',
      '.env.development',
      'config.json',
      'config.yml',
      'config.yaml',
      'settings.json',
      'settings.yml',
      'database.yml',
      'secrets.yml',
      'app.yml',
      'discourse.conf',
      'nginx.conf',
      'apache.conf',
      'httpd.conf',
      '.htaccess',
      '.htpasswd',
      'web.config',
      
      # Backup files
      'backup.sql',
      'database.sql',
      'dump.sql',
      'backup.tar.gz',
      'backup.zip',
      'site.tar.gz',
      'discourse.tar.gz',
      
      # Log files
      'error.log',
      'access.log',
      'debug.log',
      'application.log',
      'production.log',
      'development.log',
      'test.log',
      
      # Development files
      '.git/config',
      '.git/HEAD',
      '.gitignore',
      '.svn/entries',
      '.hg/hgrc',
      'Gemfile',
      'Gemfile.lock',
      'package.json',
      'package-lock.json',
      'yarn.lock',
      'composer.json',
      'composer.lock',
      'requirements.txt',
      'Pipfile',
      'Pipfile.lock',
      
      # Documentation that might contain sensitive info
      'README.md',
      'INSTALL.md',
      'CHANGELOG.md',
      'TODO.txt',
      'notes.txt',
      
      # Common admin/test files
      'admin.php',
      'test.php',
      'info.php',
      'phpinfo.php',
      'admin.html',
      'test.html',
      'admin/',
      'test/',
      'dev/',
      'development/',
      'staging/',
      
      # SSL certificates and keys
      'server.key',
      'server.crt',
      'ssl.key',
      'ssl.crt',
      'private.key',
      'public.key',
      'certificate.pem',
      'private.pem',
      
      # Common sensitive directories
      'uploads/',
      'files/',
      'documents/',
      'downloads/',
      'temp/',
      'tmp/',
      'cache/',
      'logs/',
      'backup/',
      'backups/'
    ].freeze
    
    # File extensions that might contain sensitive data
    SENSITIVE_EXTENSIONS = [
      '.sql', '.db', '.sqlite', '.sqlite3',
      '.bak', '.backup', '.old', '.orig', '.tmp', '.swp',
      '.log', '.txt', '.csv', '.xml', '.json', '.yml', '.yaml',
      '.key', '.pem', '.crt', '.cer', '.p12', '.pfx',
      '.zip', '.tar', '.tar.gz', '.rar', '.7z',
      '.doc', '.docx', '.pdf', '.xls', '.xlsx'
    ].freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
    end
    
    def scan
      results = {
        scan_type: 'file_scan',
        target_url: @target_url,
        timestamp: Time.current,
        total_files_checked: 0,
        exposed_files: [],
        sensitive_files: [],
        backup_files: [],
        config_files: [],
        vulnerabilities: [],
        recommendations: []
      }
      
      Rails.logger.info "[FileScanner] Starting file scan for #{@target_url}"
      
      begin
        # Scan for sensitive files
        scan_sensitive_files(results)
        
        # Scan for backup files with common patterns
        scan_backup_patterns(results)
        
        # Scan for directory listings
        scan_directory_listings(results)
        
        # Scan for version control files
        scan_version_control_files(results)
        
        # Scan for common admin/debug files
        scan_admin_debug_files(results)
        
        # Check file permissions and access
        check_file_permissions(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
        results[:total_files_checked] = SENSITIVE_FILES.length
        
        Rails.logger.info "[FileScanner] File scan completed. Found #{results[:exposed_files].length} exposed files"
        
      rescue => e
        Rails.logger.error "[FileScanner] Error during file scan: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def scan_sensitive_files(results)
      SENSITIVE_FILES.each do |file_path|
        begin
          response = make_request(file_path)
          
          if response && response.code.to_i == 200
            file_info = {
              path: file_path,
              status_code: response.code.to_i,
              content_type: response['content-type'],
              content_length: response['content-length'],
              size: response.body&.length || 0,
              accessible: true
            }
            
            results[:exposed_files] << file_info
            
            # Categorize the file
            categorize_file(results, file_info, response.body)
            
            # Check for sensitive content
            if contains_sensitive_content?(response.body)
              vulnerability = {
                type: 'Exposed Sensitive File',
                severity: determine_file_severity(file_path),
                file: file_path,
                description: "Sensitive file #{file_path} is publicly accessible",
                recommendation: 'Remove or protect sensitive files from public access'
              }
              
              results[:vulnerabilities] << vulnerability
            end
          end
          
        rescue => e
          Rails.logger.debug "[FileScanner] Error checking file #{file_path}: #{e.message}"
        end
        
        # Rate limiting
        sleep(0.05) if @options[:rate_limit]
      end
    end
    
    def scan_backup_patterns(results)
      backup_patterns = [
        'backup_%Y%m%d',
        'backup_%Y-%m-%d',
        'db_backup_%Y%m%d',
        'site_backup_%Y%m%d',
        'discourse_backup_%Y%m%d'
      ]
      
      # Check for backups from the last 30 days
      (0..30).each do |days_ago|
        date = Date.current - days_ago.days
        
        backup_patterns.each do |pattern|
          backup_filename = date.strftime(pattern)
          
          ['', '.sql', '.tar.gz', '.zip'].each do |extension|
            full_filename = "#{backup_filename}#{extension}"
            
            begin
              response = make_request("/#{full_filename}")
              
              if response && response.code.to_i == 200
                file_info = {
                  path: full_filename,
                  status_code: response.code.to_i,
                  content_type: response['content-type'],
                  size: response.body&.length || 0,
                  date: date
                }
                
                results[:backup_files] << file_info
                
                vulnerability = {
                  type: 'Exposed Backup File',
                  severity: 'Critical',
                  file: full_filename,
                  description: "Backup file #{full_filename} is publicly accessible",
                  recommendation: 'Remove backup files from public directories and store securely'
                }
                
                results[:vulnerabilities] << vulnerability
              end
              
            rescue => e
              Rails.logger.debug "[FileScanner] Error checking backup pattern #{full_filename}: #{e.message}"
            end
          end
        end
      end
    end
    
    def scan_directory_listings(results)
      common_directories = [
        '/',
        '/admin/',
        '/uploads/',
        '/files/',
        '/backup/',
        '/logs/',
        '/temp/',
        '/cache/',
        '/assets/',
        '/public/',
        '/private/',
        '/config/',
        '/lib/',
        '/app/',
        '/vendor/'
      ]
      
      common_directories.each do |directory|
        begin
          response = make_request(directory)
          
          if response && response.code.to_i == 200
            # Check if response contains directory listing
            if directory_listing?(response.body)
              vulnerability = {
                type: 'Directory Listing Enabled',
                severity: 'Medium',
                directory: directory,
                description: "Directory listing is enabled for #{directory}",
                recommendation: 'Disable directory listing to prevent information disclosure'
              }
              
              results[:vulnerabilities] << vulnerability
            end
          end
          
        rescue => e
          Rails.logger.debug "[FileScanner] Error checking directory #{directory}: #{e.message}"
        end
      end
    end
    
    def scan_version_control_files(results)
      vcs_files = [
        '.git/config',
        '.git/HEAD',
        '.git/index',
        '.git/logs/HEAD',
        '.svn/entries',
        '.svn/wc.db',
        '.hg/hgrc',
        '.hg/store/00manifest.i',
        '.bzr/branch/branch.conf',
        'CVS/Entries',
        'CVS/Root'
      ]
      
      vcs_files.each do |vcs_file|
        begin
          response = make_request("/#{vcs_file}")
          
          if response && response.code.to_i == 200
            vulnerability = {
              type: 'Exposed Version Control File',
              severity: 'High',
              file: vcs_file,
              description: "Version control file #{vcs_file} is publicly accessible",
              recommendation: 'Remove version control directories from production servers'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
        rescue => e
          Rails.logger.debug "[FileScanner] Error checking VCS file #{vcs_file}: #{e.message}"
        end
      end
    end
    
    def scan_admin_debug_files(results)
      admin_debug_files = [
        'admin.php',
        'admin.html',
        'admin.asp',
        'admin.aspx',
        'test.php',
        'test.html',
        'info.php',
        'phpinfo.php',
        'debug.php',
        'debug.html',
        'console.php',
        'shell.php',
        'webshell.php'
      ]
      
      admin_debug_files.each do |file|
        begin
          response = make_request("/#{file}")
          
          if response && response.code.to_i == 200
            severity = file.include?('shell') ? 'Critical' : 'High'
            
            vulnerability = {
              type: 'Exposed Admin/Debug File',
              severity: severity,
              file: file,
              description: "Admin/debug file #{file} is publicly accessible",
              recommendation: 'Remove admin and debug files from production servers'
            }
            
            results[:vulnerabilities] << vulnerability
          end
          
        rescue => e
          Rails.logger.debug "[FileScanner] Error checking admin/debug file #{file}: #{e.message}"
        end
      end
    end
    
    def check_file_permissions(results)
      # This would check file permissions if we had server access
      # For web-based scanning, we can only check what's publicly accessible
      
      # Check for files that should not be publicly readable
      protected_files = ['.env', 'database.yml', 'secrets.yml', 'config.yml']
      
      results[:exposed_files].each do |file_info|
        if protected_files.any? { |pf| file_info[:path].include?(pf) }
          vulnerability = {
            type: 'Improper File Permissions',
            severity: 'Critical',
            file: file_info[:path],
            description: "Protected file #{file_info[:path]} has improper permissions",
            recommendation: 'Set proper file permissions to prevent unauthorized access'
          }
          
          results[:vulnerabilities] << vulnerability
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
    
    def categorize_file(results, file_info, content)
      file_path = file_info[:path]
      
      if file_path.match?(/\.(sql|db|sqlite|backup|bak|old)$/i)
        results[:backup_files] << file_info
      elsif file_path.match?(/\.(yml|yaml|json|conf|config|env)$/i)
        results[:config_files] << file_info
      elsif content && contains_sensitive_content?(content)
        results[:sensitive_files] << file_info
      end
    end
    
    def contains_sensitive_content?(content)
      return false unless content
      
      sensitive_patterns = [
        /password\s*[=:]/i,
        /secret\s*[=:]/i,
        /api[_-]?key\s*[=:]/i,
        /private[_-]?key/i,
        /database[_-]?url/i,
        /connection[_-]?string/i,
        /smtp[_-]?password/i,
        /access[_-]?token/i,
        /auth[_-]?token/i,
        /session[_-]?secret/i,
        /encryption[_-]?key/i,
        /-----BEGIN (RSA )?PRIVATE KEY-----/,
        /-----BEGIN CERTIFICATE-----/
      ]
      
      sensitive_patterns.any? { |pattern| content.match?(pattern) }
    end
    
    def determine_file_severity(file_path)
      case file_path
      when /\.(env|key|pem|p12|pfx)$/i
        'Critical'
      when /\.(sql|db|backup|bak)$/i
        'High'
      when /\.(yml|yaml|json|conf|config)$/i
        'High'
      when /\.(log|txt)$/i
        'Medium'
      else
        'Low'
      end
    end
    
    def directory_listing?(content)
      return false unless content
      
      listing_indicators = [
        'Index of /',
        'Directory listing for',
        '<title>Index of',
        'Parent Directory',
        '[DIR]',
        '[   ]',
        'Last modified'
      ]
      
      listing_indicators.any? { |indicator| content.include?(indicator) }
    end
    
    def generate_recommendations(results)
      recommendations = []
      
      # Group vulnerabilities by type
      vuln_types = results[:vulnerabilities].group_by { |v| v[:type] }
      
      if vuln_types['Exposed Sensitive File']
        recommendations << 'Remove or protect sensitive files from public web directories'
      end
      
      if vuln_types['Exposed Backup File']
        recommendations << 'Store backup files in secure locations outside of web root'
      end
      
      if vuln_types['Directory Listing Enabled']
        recommendations << 'Disable directory listing in web server configuration'
      end
      
      if vuln_types['Exposed Version Control File']
        recommendations << 'Remove version control directories from production servers'
      end
      
      if vuln_types['Exposed Admin/Debug File']
        recommendations << 'Remove admin and debug files from production environment'
      end
      
      if vuln_types['Improper File Permissions']
        recommendations << 'Review and set proper file permissions for sensitive files'
      end
      
      if results[:exposed_files].length > 10
        recommendations << 'Implement comprehensive file access controls and regular security audits'
      end
      
      results[:recommendations] = recommendations
    end
  end
end