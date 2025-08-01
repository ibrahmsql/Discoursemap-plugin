# frozen_string_literal: true
  
# name: discoursemap
# about: Professional security auditing plugin for Discourse - Comprehensive vulnerability assessment and security analysis
# version: 1.0.0
# authors: İbrahimsql
# url: https://github.com/ibrahmsql/discoursemap-plugin
# required_version: 2.7.0
# transpile_js: true

enabled_site_setting :discoursemap_enabled

after_initialize do
  # Load security scanning modules
  require_relative 'lib/discoursemap_scanner'
  require_relative 'lib/vulnerability_scanner'
  require_relative 'lib/plugin_scanner'
  require_relative 'lib/theme_scanner'
  require_relative 'lib/user_scanner'
  require_relative 'lib/endpoint_scanner'
  require_relative 'lib/config_scanner'
  require_relative 'lib/database_scanner'
  require_relative 'lib/file_scanner'
  require_relative 'lib/network_scanner'
  require_relative 'lib/report_generator'
  
  # Load admin controller
  require_relative 'app/controllers/admin/discoursemap_controller'
  
  # Define routes
  Discourse::Application.routes.append do
    namespace :admin, constraints: StaffConstraint.new do
      resources :discoursemap, only: [:index, :show, :create] do
        collection do
          post :start_scan
          get :scan_status
          get :scan_results
          delete :clear_results
          get :export_report
        end
      end
    end
  end
  
  # Scheduled job for security scanning
  require_relative 'app/jobs/scheduled/security_scan_job'
  
  # API endpoints
  require_relative 'app/serializers/security_scan_serializer'
  
  # Model for security scan results
  require_relative 'app/models/security_scan_result'
end

# Site settings
register_asset "stylesheets/admin/discoursemap.scss"
  register_asset "javascripts/discourse/templates/admin/plugins-discoursemap.hbs"
  register_asset "javascripts/discourse/controllers/admin-plugins-discoursemap.js.es6"
register_asset "javascripts/discourse/routes/admin-discoursemap.js"

# Add to admin menu
add_admin_route 'discoursemap.title', 'discoursemap'

# Security scanning permission
add_to_class(:user, :can_run_discoursemap?) do
  staff?
end