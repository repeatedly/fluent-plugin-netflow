require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'test/unit'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'fluent/test'

# $log = Fluent::Log.new(Fluent::Test::DummyLogDevice.new, Fluent::Log::LEVEL_INFO)

require 'fluent/plugin/parser_netflow'
require 'fluent/plugin/in_netflow'

def unused_port
  s = TCPServer.open(0)
  port = s.addr[1]
  s.close
  port
end
