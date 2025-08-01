# DiscourseMap - Professional Security Analysis Plugin

🔒 **Professional security auditing plugin for Discourse** - Comprehensive vulnerability assessment and security analysis

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/ibrahmsql/discoursemap-plugin)
[![Discourse](https://img.shields.io/badge/discourse-2.7.0+-orange.svg)](https://www.discourse.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🚀 Features

### 🛡️ Comprehensive Security Scanning
- **Vulnerability Scanner**: Detects known security vulnerabilities
- **Plugin Scanner**: Analyzes installed plugins for security issues
- **Theme Scanner**: Scans themes for potential security risks
- **User Scanner**: Audits user permissions and access controls
- **Endpoint Scanner**: Tests API endpoints for vulnerabilities
- **Config Scanner**: Reviews configuration settings for security
- **Database Scanner**: Analyzes database security configurations
- **File Scanner**: Scans files for malicious content
- **Network Scanner**: Performs network security assessments

### 📊 Reporting
- **Multi-format Reports**: PDF, JSON, CSV export options
- **Risk Assessment**: Automated risk scoring and categorization
- **Compliance Checking**: Security compliance verification
- **Detailed Analysis**: In-depth vulnerability descriptions
- **Recommendations**: Actionable security improvement suggestions

### 🎯 Modern Admin Interface
- **Real-time Scanning**: Live scan progress monitoring
- **Interactive Dashboard**: Modern, responsive admin panel
- **Scan History**: Complete audit trail of all scans
- **Modular Selection**: Choose specific scan modules
- **Target Configuration**: Flexible target URL settings

## 📦 Installation

### Prerequisites
- Discourse 2.7.0 or higher
- Ruby 2.7+ / 3.0+
- Admin access to Discourse installation

### Installation Steps

1. **Clone the plugin**:
   ```bash
   cd /var/discourse/containers/app/plugins
   git clone https://github.com/ibrahmsql/discoursemap-plugin.git
   ```

2. **Rebuild Discourse**:
   ```bash
   cd /var/discourse
   ./launcher rebuild app
   ```

3. **Enable the plugin**:
   - Go to Admin → Settings → Plugins
   - Find "DiscourseMap" and enable it
   - Configure the `discoursemap_enabled` setting

## 🔧 Configuration

### Site Settings

Navigate to **Admin → Settings → Plugins → DiscourseMap**:

- `discoursemap_enabled`: Enable/disable the plugin
- Configure scan modules and security thresholds
- Set up automated scanning schedules

### Admin Panel Access

Access DiscourseMap at:
```
https://your-discourse-site.com/admin/plugins/discoursemap
```

## 🎮 Usage

### Starting a Security Scan

1. **Navigate to Admin Panel**:
   - Go to Admin → Plugins → DiscourseMap

2. **Configure Scan Settings**:
   - Enter target URL (your Discourse site)
   - Select scan modules to run
   - Choose scan intensity level

3. **Run the Scan**:
   - Click "Start Security Scan"
   - Monitor real-time progress
   - View results as they appear

### Understanding Results

#### Risk Levels
- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Address within 24 hours
- 🟡 **Medium**: Address within a week
- 🟢 **Low**: Monitor and address when convenient
- ℹ️ **Info**: Informational findings

#### Scan Modules

| Module | Description | Risk Focus |
|--------|-------------|------------|
| Vulnerability | Known CVEs and security flaws | Critical |
| Plugin | Third-party plugin security | High |
| Theme | Theme code vulnerabilities | Medium |
| User | Access control issues | High |
| Endpoint | API security testing | Medium |
| Config | Configuration hardening | Medium |
| Database | Database security | High |
| File | Malicious file detection | Critical |
| Network | Network security assessment | Medium |

### Exporting Reports

- **PDF Report**: Comprehensive executive summary
- **JSON Export**: Machine-readable detailed results
- **CSV Export**: Spreadsheet-compatible vulnerability list

## 🛠️ Development

### Project Structure

```
discoursemap/
├── plugin.rb                 # Main plugin file
├── app/
│   ├── controllers/
│   │   └── admin/
│   │       └── discoursemap_controller.rb
│   └── jobs/
│       └── scheduled/
├── assets/
│   ├── javascripts/
│   │   └── discourse/
│   │       ├── controllers/
│   │       └── templates/
│   └── stylesheets/
├── config/
│   ├── locales/              # Internationalization
│   └── settings.yml          # Plugin settings
└── lib/                      # Core scanning modules
    ├── discoursemap_scanner.rb
    ├── vulnerability_scanner.rb
    ├── network_scanner.rb
    └── ...
```

### Adding Custom Scanners

1. Create a new scanner in `lib/`:
   ```ruby
   module DiscourseMap
     class CustomScanner
       include ActiveModel::Serialization
       
       def initialize(target_url, options = {})
         @target_url = target_url
         @options = options
       end
       
       def scan
         # Your scanning logic here
       end
     end
   end
   ```

2. Register in `lib/discoursemap_scanner.rb`
3. Add to admin interface

### Running Tests

```bash
# Run plugin tests
cd /var/discourse
bundle exec rake plugin:spec[discourse-discoursemap]
```

## 🌍 Internationalization

Supported languages:
- 🇺🇸 English (en)
- 🇹🇷 Turkish (tr)

To add a new language:
1. Create locale files in `config/locales/`
2. Follow existing translation structure
3. Submit a pull request

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style

- Follow Ruby style guide
- Use meaningful variable names
- Add comments for complex logic
- Write tests for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/ibrahmsql/discoursemap-plugin/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ibrahmsql/discoursemap-plugin/discussions)
- **Documentation**: [Wiki](https://github.com/ibrahmsql/discoursemap-plugin/wiki)

## 🙏 Acknowledgments

- Discourse team for the excellent platform
- Security research community
- All contributors and testers

## 📊 Statistics

- **Scan Modules**: 9 comprehensive modules
- **Vulnerability Database**: 1000+ known issues
- **Report Formats**: 3 export options
- **Languages**: 2 supported languages

---

**Made with ❤️ by [İbrahimsql](https://github.com/ibrahmsql)**

*Securing Discourse communities, one scan at a time.*
