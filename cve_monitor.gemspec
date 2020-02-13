# Ensure we require the local version and not one we might have installed already
require File.join([File.dirname(__FILE__),'lib','cve_monitor','version.rb'])
spec = Gem::Specification.new do |s|
  s.name = 'cve_monitor'
  s.version = CveMonitor::VERSION
  s.author = 'Jeremy Symon'
  s.email = 'jeremy@symon.nz'
  s.homepage = 'https://github.com/jtsymon/cve_monitor'
  s.platform = Gem::Platform::RUBY
  s.summary = 'Monitor CVEs for a list of CPEs'
  s.files = `git ls-files`.split("
")
  s.require_paths << 'lib'
  s.extra_rdoc_files = ['README.rdoc','cve_monitor.rdoc']
  s.rdoc_options << '--title' << 'cve_monitor' << '--main' << 'README.rdoc' << '-ri'
  s.bindir = 'bin'
  s.executables << 'cve_monitor'
  s.add_development_dependency('rake')
  s.add_development_dependency('rdoc')
  s.add_development_dependency('aruba')
  s.add_runtime_dependency('gli','2.19.0')
  s.add_runtime_dependency('cpe23','0.1.0')
end
