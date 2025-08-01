# frozen_string_literal: true

module DiscourseMap
  class NetworkScanner
    include ActiveModel::Serialization
    
    attr_accessor :target_url, :options
    
    # Common ports to scan
    COMMON_PORTS = [
      21,   # FTP
      22,   # SSH
      23,   # Telnet
      25,   # SMTP
      53,   # DNS
      80,   # HTTP
      110,  # POP3
      143,  # IMAP
      443,  # HTTPS
      993,  # IMAPS
      995,  # POP3S
      1433, # MSSQL
      3306, # MySQL
      5432, # PostgreSQL
      6379, # Redis
      8080, # HTTP Alt
      8443, # HTTPS Alt
      9200, # Elasticsearch
      27017 # MongoDB
    ].freeze
    
    # Dangerous ports that should not be exposed
    DANGEROUS_PORTS = [
      21,   # FTP
      23,   # Telnet
      135,  # RPC
      139,  # NetBIOS
      445,  # SMB
      1433, # MSSQL
      3306, # MySQL
      3389, # RDP
      5432, # PostgreSQL
      5900, # VNC
      6379, # Redis
      9200, # Elasticsearch
      27017 # MongoDB
    ].freeze
    
    def initialize(target_url, options = {})
      @target_url = target_url
      @options = options
      @host = URI.parse(target_url).host
    end
    
    def scan
      results = {
        scan_type: 'network_scan',
        target_url: @target_url,
        target_host: @host,
        timestamp: Time.current,
        open_ports: [],
        closed_ports: [],
        filtered_ports: [],
        services: {},
        vulnerabilities: [],
        recommendations: []
      }
      
      Rails.logger.info "[DiscourseMap] Starting network scan for #{@host}"
      
      begin
        # Perform port scan
        perform_port_scan(results)
        
        # Check for dangerous exposed services
        check_dangerous_services(results)
        
        # Perform service detection
        detect_services(results)
        
        # Check SSL/TLS configuration
        check_ssl_tls_config(results)
        
        # Check for common network vulnerabilities
        check_network_vulnerabilities(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
        Rails.logger.info "[DiscourseMap] Network scan completed. Found #{results[:open_ports].length} open ports"
        
      rescue => e
        Rails.logger.error "[DiscourseMap] Error during network scan: #{e.message}"
        results[:error] = e.message
      end
      
      results
    end
    
    private
    
    def perform_port_scan(results)
      ports_to_scan = @options[:ports] || COMMON_PORTS
      timeout = @options[:timeout] || 3
      
      ports_to_scan.each do |port|
        begin
          socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
          
          begin
            # Set timeout for connection
            socket.connect_nonblock(Socket.sockaddr_in(port, @host))
            
            # Port is open
            results[:open_ports] << {
              port: port,
              protocol: 'tcp',
              service: get_service_name(port),
              state: 'open'
            }
            
          rescue IO::WaitWritable
            # Connection in progress, wait for completion
            if IO.select(nil, [socket], nil, timeout)
              begin
                socket.connect_nonblock(Socket.sockaddr_in(port, @host))
                # Connection successful
                results[:open_ports] << {
                  port: port,
                  protocol: 'tcp',
                  service: get_service_name(port),
                  state: 'open'
                }
              rescue Errno::EISCONN
                # Already connected
                results[:open_ports] << {
                  port: port,
                  protocol: 'tcp',
                  service: get_service_name(port),
                  state: 'open'
                }
              rescue => e
                # Connection failed
                results[:closed_ports] << {
                  port: port,
                  protocol: 'tcp',
                  state: 'closed'
                }
              end
            else
              # Timeout
              results[:filtered_ports] << {
                port: port,
                protocol: 'tcp',
                state: 'filtered'
              }
            end
          rescue Errno::ECONNREFUSED
            # Port is closed
            results[:closed_ports] << {
              port: port,
              protocol: 'tcp',
              state: 'closed'
            }
          rescue => e
            # Other error (filtered, unreachable, etc.)
            results[:filtered_ports] << {
              port: port,
              protocol: 'tcp',
              state: 'filtered',
              error: e.message
            }
          ensure
            socket.close rescue nil
          end
          
        rescue => e
          Rails.logger.debug "[DiscourseMap] Error scanning port #{port}: #{e.message}"
        end
        
        # Rate limiting
        sleep(0.1) if @options[:rate_limit]
      end
    end
    
    def check_dangerous_services(results)
      results[:open_ports].each do |port_info|
        port = port_info[:port]
        
        if DANGEROUS_PORTS.include?(port)
          severity = determine_port_severity(port)
          
          vulnerability = {
            type: 'Dangerous Service Exposed',
            severity: severity,
            port: port,
            service: port_info[:service],
            description: "Dangerous service #{port_info[:service]} is exposed on port #{port}",
            recommendation: get_port_recommendation(port)
          }
          
          results[:vulnerabilities] << vulnerability
        end
      end
    end
    
    def detect_services(results)
      results[:open_ports].each do |port_info|
        port = port_info[:port]
        
        begin
          service_info = detect_service_on_port(port)
          
          if service_info
            results[:services][port] = service_info
            port_info.merge!(service_info)
            
            # Check for service-specific vulnerabilities
            check_service_vulnerabilities(results, port, service_info)
          end
          
        rescue => e
          Rails.logger.debug "[DiscourseMap] Error detecting service on port #{port}: #{e.message}"
        end
      end
    end
    
    def detect_service_on_port(port)
      timeout = @options[:timeout] || 5
      
      begin
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        socket.connect(Socket.sockaddr_in(port, @host))
        
        # Send appropriate probe based on port
        probe_data = get_service_probe(port)
        socket.write(probe_data) if probe_data
        
        # Read response
        response = ''
        begin
          Timeout::timeout(timeout) do
            response = socket.read(1024)
          end
        rescue Timeout::Error
          # No response within timeout
        end
        
        socket.close
        
        # Analyze response
        analyze_service_response(port, response)
        
      rescue => e
        Rails.logger.debug "[DiscourseMap] Error probing service on port #{port}: #{e.message}"
        nil
      end
    end
    
    def check_ssl_tls_config(results)
      ssl_ports = results[:open_ports].select { |p| [443, 8443, 993, 995].include?(p[:port]) }
      
      ssl_ports.each do |port_info|
        port = port_info[:port]
        
        begin
          ssl_info = analyze_ssl_configuration(port)
          
          if ssl_info
            results[:services][port] ||= {}
            results[:services][port][:ssl] = ssl_info
            
            # Check for SSL/TLS vulnerabilities
            check_ssl_vulnerabilities(results, port, ssl_info)
          end
          
        rescue => e
          Rails.logger.debug "[DiscourseMap] Error checking SSL on port #{port}: #{e.message}"
        end
      end
    end
    
    def analyze_ssl_configuration(port)
      begin
        tcp_socket = TCPSocket.new(@host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.connect
        
        cert = ssl_socket.peer_cert
        cipher = ssl_socket.cipher
        
        ssl_info = {
          protocol: ssl_socket.ssl_version,
          cipher_suite: cipher[0],
          cipher_bits: cipher[2],
          certificate: {
            subject: cert.subject.to_s,
            issuer: cert.issuer.to_s,
            not_before: cert.not_before,
            not_after: cert.not_after,
            signature_algorithm: cert.signature_algorithm
          }
        }
        
        ssl_socket.close
        tcp_socket.close
        
        ssl_info
        
      rescue => e
        Rails.logger.debug "[DiscourseMap] Error analyzing SSL on port #{port}: #{e.message}"
        nil
      end
    end
    
    def check_ssl_vulnerabilities(results, port, ssl_info)
      # Check for weak protocols
      if ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'].include?(ssl_info[:protocol])
        vulnerability = {
          type: 'Weak SSL/TLS Protocol',
          severity: 'High',
          port: port,
          protocol: ssl_info[:protocol],
          description: "Weak SSL/TLS protocol #{ssl_info[:protocol]} is supported",
          recommendation: 'Disable weak SSL/TLS protocols and use TLS 1.2 or higher'
        }
        
        results[:vulnerabilities] << vulnerability
      end
      
      # Check for weak ciphers
      weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
      cipher_suite = ssl_info[:cipher_suite]
      
      if weak_ciphers.any? { |weak| cipher_suite.include?(weak) }
        vulnerability = {
          type: 'Weak SSL/TLS Cipher',
          severity: 'Medium',
          port: port,
          cipher: cipher_suite,
          description: "Weak cipher suite #{cipher_suite} is supported",
          recommendation: 'Configure strong cipher suites and disable weak ones'
        }
        
        results[:vulnerabilities] << vulnerability
      end
      
      # Check certificate expiration
      cert = ssl_info[:certificate]
      days_until_expiry = (cert[:not_after] - Time.current) / 1.day
      
      if days_until_expiry < 30
        severity = days_until_expiry < 7 ? 'Critical' : 'High'
        
        vulnerability = {
          type: 'SSL Certificate Expiring',
          severity: severity,
          port: port,
          expires: cert[:not_after],
          days_remaining: days_until_expiry.to_i,
          description: "SSL certificate on port #{port} expires in #{days_until_expiry.to_i} days",
          recommendation: 'Renew SSL certificate before expiration'
        }
        
        results[:vulnerabilities] << vulnerability
      end
      
      # Check for weak signature algorithm
      if cert[:signature_algorithm].include?('sha1')
        vulnerability = {
          type: 'Weak Certificate Signature',
          severity: 'Medium',
          port: port,
          algorithm: cert[:signature_algorithm],
          description: "SSL certificate uses weak signature algorithm: #{cert[:signature_algorithm]}",
          recommendation: 'Use certificate with SHA-256 or stronger signature algorithm'
        }
        
        results[:vulnerabilities] << vulnerability
      end
    end
    
    def check_network_vulnerabilities(results)
      # Check for common network-level vulnerabilities
      
      # Check if both HTTP and HTTPS are available
      http_open = results[:open_ports].any? { |p| p[:port] == 80 }
      https_open = results[:open_ports].any? { |p| p[:port] == 443 }
      
      if http_open && https_open
        # Check if HTTP redirects to HTTPS
        unless http_redirects_to_https?
          vulnerability = {
            type: 'HTTP Not Redirected to HTTPS',
            severity: 'Medium',
            description: 'HTTP traffic is not automatically redirected to HTTPS',
            recommendation: 'Configure HTTP to HTTPS redirection for all traffic'
          }
          
          results[:vulnerabilities] << vulnerability
        end
      elsif http_open && !https_open
        vulnerability = {
          type: 'No HTTPS Available',
          severity: 'High',
          description: 'HTTPS is not available, only HTTP',
          recommendation: 'Enable HTTPS with proper SSL/TLS configuration'
        }
        
        results[:vulnerabilities] << vulnerability
      end
      
      # Check for unnecessary services
      unnecessary_services = results[:open_ports].select do |port_info|
        ![80, 443, 22].include?(port_info[:port]) # Keep only essential ports
      end
      
      if unnecessary_services.length > 3
        vulnerability = {
          type: 'Too Many Open Ports',
          severity: 'Medium',
          open_ports: unnecessary_services.map { |p| p[:port] },
          description: "#{unnecessary_services.length} potentially unnecessary ports are open",
          recommendation: 'Close unnecessary ports and services to reduce attack surface'
        }
        
        results[:vulnerabilities] << vulnerability
      end
    end
    
    def check_service_vulnerabilities(results, port, service_info)
      # Check for service-specific vulnerabilities based on detected service
      service_name = service_info[:name] || get_service_name(port)
      
      case service_name.downcase
      when 'ssh'
        check_ssh_vulnerabilities(results, port, service_info)
      when 'ftp'
        check_ftp_vulnerabilities(results, port, service_info)
      when 'mysql'
        check_mysql_vulnerabilities(results, port, service_info)
      when 'postgresql'
        check_postgresql_vulnerabilities(results, port, service_info)
      when 'redis'
        check_redis_vulnerabilities(results, port, service_info)
      end
    end
    
    def check_ssh_vulnerabilities(results, port, service_info)
      # SSH should not be on default port 22 for security
      if port == 22
        vulnerability = {
          type: 'SSH on Default Port',
          severity: 'Low',
          port: port,
          description: 'SSH is running on default port 22',
          recommendation: 'Consider changing SSH to a non-standard port'
        }
        
        results[:vulnerabilities] << vulnerability
      end
    end
    
    def check_ftp_vulnerabilities(results, port, service_info)
      vulnerability = {
        type: 'Insecure FTP Service',
        severity: 'High',
        port: port,
        description: 'FTP service is running (transmits credentials in plaintext)',
        recommendation: 'Replace FTP with SFTP or FTPS for secure file transfer'
      }
      
      results[:vulnerabilities] << vulnerability
    end
    
    def check_mysql_vulnerabilities(results, port, service_info)
      vulnerability = {
        type: 'Database Service Exposed',
        severity: 'Critical',
        port: port,
        service: 'MySQL',
        description: 'MySQL database service is exposed to the internet',
        recommendation: 'Restrict database access to authorized hosts only'
      }
      
      results[:vulnerabilities] << vulnerability
    end
    
    def check_postgresql_vulnerabilities(results, port, service_info)
      vulnerability = {
        type: 'Database Service Exposed',
        severity: 'Critical',
        port: port,
        service: 'PostgreSQL',
        description: 'PostgreSQL database service is exposed to the internet',
        recommendation: 'Restrict database access to authorized hosts only'
      }
      
      results[:vulnerabilities] << vulnerability
    end
    
    def check_redis_vulnerabilities(results, port, service_info)
      vulnerability = {
        type: 'Cache Service Exposed',
        severity: 'Critical',
        port: port,
        service: 'Redis',
        description: 'Redis cache service is exposed to the internet',
        recommendation: 'Restrict Redis access and enable authentication'
      }
      
      results[:vulnerabilities] << vulnerability
    end
    
    # Helper methods
    
    def get_service_name(port)
      service_map = {
        21 => 'FTP',
        22 => 'SSH',
        23 => 'Telnet',
        25 => 'SMTP',
        53 => 'DNS',
        80 => 'HTTP',
        110 => 'POP3',
        143 => 'IMAP',
        443 => 'HTTPS',
        993 => 'IMAPS',
        995 => 'POP3S',
        1433 => 'MSSQL',
        3306 => 'MySQL',
        5432 => 'PostgreSQL',
        6379 => 'Redis',
        8080 => 'HTTP-Alt',
        8443 => 'HTTPS-Alt',
        9200 => 'Elasticsearch',
        27017 => 'MongoDB'
      }
      
      service_map[port] || 'Unknown'
    end
    
    def determine_port_severity(port)
      case port
      when 21, 23, 1433, 3306, 5432, 6379, 9200, 27017
        'Critical'
      when 135, 139, 445, 3389, 5900
        'High'
      else
        'Medium'
      end
    end
    
    def get_port_recommendation(port)
      recommendations = {
        21 => 'Disable FTP or replace with SFTP/FTPS',
        23 => 'Disable Telnet and use SSH instead',
        1433 => 'Restrict MSSQL access to authorized hosts only',
        3306 => 'Restrict MySQL access to authorized hosts only',
        5432 => 'Restrict PostgreSQL access to authorized hosts only',
        6379 => 'Restrict Redis access and enable authentication',
        9200 => 'Restrict Elasticsearch access and enable security features',
        27017 => 'Restrict MongoDB access and enable authentication'
      }
      
      recommendations[port] || 'Review if this service needs to be publicly accessible'
    end
    
    def get_service_probe(port)
      probes = {
        21 => nil, # FTP sends banner automatically
        22 => nil, # SSH sends banner automatically
        25 => "EHLO test\r\n",
        80 => "GET / HTTP/1.0\r\n\r\n",
        110 => nil, # POP3 sends banner automatically
        143 => nil, # IMAP sends banner automatically
        443 => nil, # HTTPS requires SSL handshake
        3306 => nil, # MySQL sends banner automatically
        5432 => nil # PostgreSQL sends banner automatically
      }
      
      probes[port]
    end
    
    def analyze_service_response(port, response)
      return nil unless response && !response.empty?
      
      service_info = { response: response[0..200] } # Limit response size
      
      case port
      when 21
        if response.include?('FTP')
          service_info[:name] = 'FTP'
          service_info[:version] = extract_version(response)
        end
      when 22
        if response.include?('SSH')
          service_info[:name] = 'SSH'
          service_info[:version] = extract_ssh_version(response)
        end
      when 80, 8080
        if response.include?('HTTP')
          service_info[:name] = 'HTTP'
          service_info[:server] = extract_server_header(response)
        end
      when 3306
        if response.include?('mysql') || response.bytes[0] == 10
          service_info[:name] = 'MySQL'
          service_info[:version] = extract_mysql_version(response)
        end
      end
      
      service_info
    end
    
    def extract_version(response)
      # Extract version information from service banner
      version_match = response.match(/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/)
      version_match ? version_match[1] : 'Unknown'
    end
    
    def extract_ssh_version(response)
      ssh_match = response.match(/SSH-([0-9\.]+)/)
      ssh_match ? ssh_match[1] : 'Unknown'
    end
    
    def extract_server_header(response)
      server_match = response.match(/Server: ([^\r\n]+)/)
      server_match ? server_match[1] : 'Unknown'
    end
    
    def extract_mysql_version(response)
      # MySQL version extraction from handshake packet
      'Unknown' # Simplified for this implementation
    end
    
    def http_redirects_to_https?
      begin
        uri = URI("http://#{@host}")
        
        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = 5
        http.read_timeout = 5
        
        request = Net::HTTP::Get.new('/')
        response = http.request(request)
        
        # Check if response is a redirect to HTTPS
        if [301, 302, 307, 308].include?(response.code.to_i)
          location = response['location']
          return location && location.start_with?('https://')
        end
        
        false
        
      rescue => e
        Rails.logger.debug "[DiscourseMap] Error checking HTTP redirect: #{e.message}"
        false
      end
    end
    
    def generate_recommendations(results)
      recommendations = []
      
      # Group vulnerabilities by type
      vuln_types = results[:vulnerabilities].group_by { |v| v[:type] }
      
      if vuln_types['Dangerous Service Exposed']
        recommendations << 'Close or restrict access to dangerous services'
      end
      
      if vuln_types['Weak SSL/TLS Protocol']
        recommendations << 'Update SSL/TLS configuration to use secure protocols'
      end
      
      if vuln_types['Database Service Exposed']
        recommendations << 'Implement database access controls and firewall rules'
      end
      
      if vuln_types['No HTTPS Available']
        recommendations << 'Implement HTTPS with proper SSL/TLS configuration'
      end
      
      if results[:open_ports].length > 5
        recommendations << 'Review and minimize the number of exposed services'
      end
      
      results[:recommendations] = recommendations
    end
  end
end