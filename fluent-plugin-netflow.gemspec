# encoding: utf-8
$:.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |gem|
  gem.name        = "fluent-plugin-netflow"
  gem.description = "Netflow plugin for Fluentd"
  gem.homepage    = "https://github.com/repeatedly/fluent-plugin-netflow"
  gem.summary     = gem.description
  gem.version     = File.read("VERSION").strip
  gem.authors     = ["Masahiro Nakagawa"]
  gem.email       = "repeatedly@gmail.com"
  #gem.platform    = Gem::Platform::RUBY
  gem.license     = 'Apache License (2.0)'
  gem.files       = `git ls-files`.split("\n")
  gem.test_files  = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ['lib']

  gem.add_dependency "fluentd", [">= 0.14.10", "< 2"]
  gem.add_dependency "bindata", "~> 2.1"
  gem.add_development_dependency "rake", ">= 0.9.2"
  gem.add_development_dependency "test-unit", "~> 3.0"
end
