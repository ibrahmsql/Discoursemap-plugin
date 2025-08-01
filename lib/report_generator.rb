# frozen_string_literal: true

module DiscourseMap
  class ReportGenerator
    include ActiveModel::Serialization
    
    attr_accessor :scan_results, :options
    
    SEVERITY_COLORS = {
      'Critical' => '#dc3545',
      'High' => '#fd7e14',
      'Medium' => '#ffc107',
      'Low' => '#28a745',
      'Info' => '#17a2b8'
    }.freeze
    
    SEVERITY_WEIGHTS = {
      'Critical' => 10,
      'High' => 7,
      'Medium' => 4,
      'Low' => 2,
      'Info' => 1
    }.freeze
    
    def initialize(scan_results, options = {})
      @scan_results = scan_results
      @options = options
    end
    
    def generate_report(format = 'json')
      case format.downcase
      when 'json'
        generate_json_report
      when 'html'
        generate_html_report
      when 'pdf'
        generate_pdf_report
      when 'csv'
        generate_csv_report
      when 'xml'
        generate_xml_report
      else
        raise ArgumentError, "Unsupported format: #{format}"
      end
    end
    
    def generate_summary
      summary = {
        scan_info: extract_scan_info,
        vulnerability_summary: generate_vulnerability_summary,
        risk_assessment: calculate_risk_assessment,
        compliance_status: check_compliance_status,
        recommendations: compile_recommendations
      }
      
      summary
    end
    
    private
    
    def generate_json_report
      report = {
        report_info: {
          generated_at: Time.current,
          format: 'json',
          version: '1.0',
          generator: 'DiscourseMap'
        },
        summary: generate_summary,
        detailed_results: @scan_results,
        statistics: generate_statistics
      }
      
      JSON.pretty_generate(report)
    end
    
    def generate_html_report
      summary = generate_summary
      statistics = generate_statistics
      
      html_content = <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Discourse Security Scan Report</title>
            <style>
                #{generate_css_styles}
            </style>
        </head>
        <body>
            <div class="container">
                #{generate_html_header}
                #{generate_html_summary(summary)}
                #{generate_html_statistics(statistics)}
                #{generate_html_vulnerabilities}
                #{generate_html_recommendations(summary[:recommendations])}
                #{generate_html_detailed_results}
                #{generate_html_footer}
            </div>
        </body>
        </html>
      HTML
      
      html_content
    end
    
    def generate_pdf_report
      # This would require a PDF generation library like Prawn
      # For now, return HTML that can be converted to PDF
      html_report = generate_html_report
      
      # In a real implementation, you would use a library like:
      # require 'prawn'
      # pdf = Prawn::Document.new
      # pdf.text "Security Scan Report"
      # ...
      # pdf.render
      
      html_report # Return HTML for now
    end
    
    def generate_csv_report
      require 'csv'
      
      csv_data = []
      csv_data << ['Module', 'Vulnerability Type', 'Severity', 'Description', 'Recommendation']
      
      @scan_results.each do |module_name, module_results|
        next unless module_results.is_a?(Hash) && module_results[:vulnerabilities]
        
        module_results[:vulnerabilities].each do |vuln|
          csv_data << [
            module_name,
            vuln[:type] || 'Unknown',
            vuln[:severity] || 'Unknown',
            vuln[:description] || 'No description',
            vuln[:recommendation] || 'No recommendation'
          ]
        end
      end
      
      CSV.generate do |csv|
        csv_data.each { |row| csv << row }
      end
    end
    
    def generate_xml_report
      require 'builder'
      
      xml = Builder::XmlMarkup.new(indent: 2)
      xml.instruct!
      
      xml.security_report do
        xml.report_info do
          xml.generated_at Time.current.iso8601
          xml.format 'xml'
          xml.version '1.0'
          xml.generator 'DiscourseMap'
        end
        
        summary = generate_summary
        xml.summary do
          xml.total_vulnerabilities summary[:vulnerability_summary][:total]
          xml.critical_count summary[:vulnerability_summary][:critical]
          xml.high_count summary[:vulnerability_summary][:high]
          xml.medium_count summary[:vulnerability_summary][:medium]
          xml.low_count summary[:vulnerability_summary][:low]
          xml.risk_score summary[:risk_assessment][:risk_score]
        end
        
        xml.modules do
          @scan_results.each do |module_name, module_results|
            next unless module_results.is_a?(Hash)
            
            xml.module(name: module_name) do
              if module_results[:vulnerabilities]
                xml.vulnerabilities do
                  module_results[:vulnerabilities].each do |vuln|
                    xml.vulnerability do
                      xml.type vuln[:type]
                      xml.severity vuln[:severity]
                      xml.description vuln[:description]
                      xml.recommendation vuln[:recommendation]
                    end
                  end
                end
              end
            end
          end
        end
      end
      
      xml.target!
    end
    
    def extract_scan_info
      scan_info = @scan_results.dig(:scan_info) || {}
      
      {
        scan_id: scan_info[:scan_id],
        target_url: scan_info[:target_url],
        start_time: scan_info[:start_time],
        end_time: scan_info[:end_time],
        duration: scan_info[:duration],
        modules_scanned: @scan_results.keys.reject { |k| k == :scan_info }.length
      }
    end
    
    def generate_vulnerability_summary
      summary = {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      }
      
      @scan_results.each do |module_name, module_results|
        next unless module_results.is_a?(Hash) && module_results[:vulnerabilities]
        
        module_results[:vulnerabilities].each do |vuln|
          severity = vuln[:severity]&.downcase
          summary[:total] += 1
          
          case severity
          when 'critical'
            summary[:critical] += 1
          when 'high'
            summary[:high] += 1
          when 'medium'
            summary[:medium] += 1
          when 'low'
            summary[:low] += 1
          when 'info'
            summary[:info] += 1
          end
        end
      end
      
      summary
    end
    
    def calculate_risk_assessment
      vuln_summary = generate_vulnerability_summary
      
      # Calculate risk score based on vulnerability counts and weights
      risk_score = (
        vuln_summary[:critical] * SEVERITY_WEIGHTS['Critical'] +
        vuln_summary[:high] * SEVERITY_WEIGHTS['High'] +
        vuln_summary[:medium] * SEVERITY_WEIGHTS['Medium'] +
        vuln_summary[:low] * SEVERITY_WEIGHTS['Low'] +
        vuln_summary[:info] * SEVERITY_WEIGHTS['Info']
      )
      
      # Normalize to 0-100 scale
      max_possible_score = vuln_summary[:total] * SEVERITY_WEIGHTS['Critical']
      normalized_score = max_possible_score > 0 ? (risk_score.to_f / max_possible_score * 100).round : 0
      
      risk_level = case normalized_score
                   when 0..25
                     'Low'
                   when 26..50
                     'Medium'
                   when 51..75
                     'High'
                   else
                     'Critical'
                   end
      
      {
        risk_score: normalized_score,
        risk_level: risk_level,
        total_vulnerabilities: vuln_summary[:total],
        critical_issues: vuln_summary[:critical],
        requires_immediate_attention: vuln_summary[:critical] > 0 || vuln_summary[:high] > 3
      }
    end
    
    def check_compliance_status
      vuln_summary = generate_vulnerability_summary
      
      # Basic compliance checks
      compliance = {
        pci_dss: {
          compliant: vuln_summary[:critical] == 0 && vuln_summary[:high] < 2,
          issues: []
        },
        owasp: {
          compliant: vuln_summary[:critical] == 0,
          issues: []
        },
        gdpr: {
          compliant: true, # Would need specific GDPR-related checks
          issues: []
        }
      }
      
      # Add specific compliance issues based on vulnerabilities found
      @scan_results.each do |module_name, module_results|
        next unless module_results.is_a?(Hash) && module_results[:vulnerabilities]
        
        module_results[:vulnerabilities].each do |vuln|
          if vuln[:type]&.include?('SSL') || vuln[:type]&.include?('TLS')
            compliance[:pci_dss][:issues] << 'Weak SSL/TLS configuration detected'
          end
          
          if vuln[:type]&.include?('XSS') || vuln[:type]&.include?('Injection')
            compliance[:owasp][:issues] << 'OWASP Top 10 vulnerability detected'
          end
        end
      end
      
      compliance[:pci_dss][:issues].uniq!
      compliance[:owasp][:issues].uniq!
      
      compliance
    end
    
    def compile_recommendations
      all_recommendations = []
      
      @scan_results.each do |module_name, module_results|
        next unless module_results.is_a?(Hash) && module_results[:recommendations]
        
        module_results[:recommendations].each do |recommendation|
          all_recommendations << {
            module: module_name,
            recommendation: recommendation,
            priority: determine_recommendation_priority(recommendation)
          }
        end
      end
      
      # Sort by priority and remove duplicates
      all_recommendations.uniq { |r| r[:recommendation] }
                        .sort_by { |r| priority_order(r[:priority]) }
    end
    
    def generate_statistics
      stats = {
        modules_executed: 0,
        modules_with_issues: 0,
        total_checks_performed: 0,
        scan_duration: nil,
        most_vulnerable_module: nil,
        vulnerability_distribution: {}
      }
      
      module_vuln_counts = {}
      
      @scan_results.each do |module_name, module_results|
        next if module_name == :scan_info
        next unless module_results.is_a?(Hash)
        
        stats[:modules_executed] += 1
        
        if module_results[:vulnerabilities] && module_results[:vulnerabilities].any?
          stats[:modules_with_issues] += 1
          module_vuln_counts[module_name] = module_results[:vulnerabilities].length
        end
      end
      
      # Find most vulnerable module
      if module_vuln_counts.any?
        stats[:most_vulnerable_module] = module_vuln_counts.max_by { |k, v| v }&.first
      end
      
      # Calculate scan duration
      scan_info = @scan_results[:scan_info]
      if scan_info && scan_info[:start_time] && scan_info[:end_time]
        duration = scan_info[:end_time] - scan_info[:start_time]
        stats[:scan_duration] = "#{duration.round(2)} seconds"
      end
      
      stats
    end
    
    def determine_recommendation_priority(recommendation)
      high_priority_keywords = ['critical', 'immediate', 'urgent', 'security']
      medium_priority_keywords = ['update', 'configure', 'enable', 'disable']
      
      recommendation_lower = recommendation.downcase
      
      if high_priority_keywords.any? { |keyword| recommendation_lower.include?(keyword) }
        'High'
      elsif medium_priority_keywords.any? { |keyword| recommendation_lower.include?(keyword) }
        'Medium'
      else
        'Low'
      end
    end
    
    def priority_order(priority)
      case priority
      when 'High' then 1
      when 'Medium' then 2
      when 'Low' then 3
      else 4
      end
    end
    
    # HTML generation helper methods
    
    def generate_css_styles
      <<~CSS
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .vulnerability-item {
            background: white;
            margin: 10px 0;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #ddd;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .severity-critical { border-left-color: #{SEVERITY_COLORS['Critical']}; }
        .severity-high { border-left-color: #{SEVERITY_COLORS['High']}; }
        .severity-medium { border-left-color: #{SEVERITY_COLORS['Medium']}; }
        .severity-low { border-left-color: #{SEVERITY_COLORS['Low']}; }
        .severity-info { border-left-color: #{SEVERITY_COLORS['Info']}; }
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .recommendations {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            border-top: 1px solid #eee;
        }
      CSS
    end
    
    def generate_html_header
      <<~HTML
        <div class="header">
            <h1>🛡️ Discourse Security Scan Report</h1>
            <p>Generated on #{Time.current.strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
      HTML
    end
    
    def generate_html_summary(summary)
      risk = summary[:risk_assessment]
      vuln = summary[:vulnerability_summary]
      
      <<~HTML
        <div class="summary-grid">
            <div class="summary-card">
                <h3>🎯 Risk Assessment</h3>
                <p><strong>Risk Level:</strong> #{risk[:risk_level]}</p>
                <p><strong>Risk Score:</strong> #{risk[:risk_score]}/100</p>
                <p><strong>Total Issues:</strong> #{risk[:total_vulnerabilities]}</p>
            </div>
            <div class="summary-card">
                <h3>🔍 Vulnerability Summary</h3>
                <p><strong>Critical:</strong> #{vuln[:critical]}</p>
                <p><strong>High:</strong> #{vuln[:high]}</p>
                <p><strong>Medium:</strong> #{vuln[:medium]}</p>
                <p><strong>Low:</strong> #{vuln[:low]}</p>
            </div>
            <div class="summary-card">
                <h3>📊 Scan Information</h3>
                <p><strong>Modules Scanned:</strong> #{summary[:scan_info][:modules_scanned]}</p>
                <p><strong>Target:</strong> #{summary[:scan_info][:target_url]}</p>
                <p><strong>Duration:</strong> #{summary[:scan_info][:duration] || 'N/A'}</p>
            </div>
        </div>
      HTML
    end
    
    def generate_html_statistics(statistics)
      <<~HTML
        <div class="summary-card">
            <h3>📈 Scan Statistics</h3>
            <p><strong>Modules Executed:</strong> #{statistics[:modules_executed]}</p>
            <p><strong>Modules with Issues:</strong> #{statistics[:modules_with_issues]}</p>
            <p><strong>Most Vulnerable Module:</strong> #{statistics[:most_vulnerable_module] || 'None'}</p>
            <p><strong>Scan Duration:</strong> #{statistics[:scan_duration] || 'N/A'}</p>
        </div>
      HTML
    end
    
    def generate_html_vulnerabilities
      html = '<h2>🚨 Vulnerabilities Found</h2>'
      
      @scan_results.each do |module_name, module_results|
        next unless module_results.is_a?(Hash) && module_results[:vulnerabilities]
        next if module_results[:vulnerabilities].empty?
        
        html += "<h3>#{module_name.to_s.humanize}</h3>"
        
        module_results[:vulnerabilities].each do |vuln|
          severity = vuln[:severity]&.downcase || 'unknown'
          severity_class = "severity-#{severity}"
          severity_color = SEVERITY_COLORS[vuln[:severity]] || '#6c757d'
          
          html += <<~HTML
            <div class="vulnerability-item #{severity_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4 style="margin: 0;">#{vuln[:type] || 'Unknown Vulnerability'}</h4>
                    <span class="severity-badge" style="background-color: #{severity_color};">#{vuln[:severity] || 'Unknown'}</span>
                </div>
                <p><strong>Description:</strong> #{vuln[:description] || 'No description available'}</p>
                <p><strong>Recommendation:</strong> #{vuln[:recommendation] || 'No recommendation available'}</p>
            </div>
          HTML
        end
      end
      
      html
    end
    
    def generate_html_recommendations(recommendations)
      return '' if recommendations.empty?
      
      html = <<~HTML
        <div class="recommendations">
            <h2>💡 Recommendations</h2>
            <ol>
      HTML
      
      recommendations.each do |rec|
        priority_color = case rec[:priority]
                        when 'High' then '#dc3545'
                        when 'Medium' then '#ffc107'
                        else '#28a745'
                        end
        
        html += <<~HTML
          <li>
              <strong style="color: #{priority_color}">[#{rec[:priority]}]</strong>
              #{rec[:recommendation]}
              <small style="color: #666;"> (#{rec[:module]})</small>
          </li>
        HTML
      end
      
      html += '</ol></div>'
      html
    end
    
    def generate_html_detailed_results
      # This would include detailed results from each module
      # For brevity, we'll just include a summary
      '<h2>📋 Detailed Results</h2><p>Detailed scan results are available in the JSON export.</p>'
    end
    
    def generate_html_footer
      <<~HTML
        <div class="footer">
            <p>Report generated by DiscourseMap v1.0</p>
            <p>For questions or support, please contact your security team.</p>
        </div>
      HTML
    end
  end
end