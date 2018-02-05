#
# Fluent
#
# Copyright (C) 2014 Masahiro Nakagawa
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

require 'fluent/plugin/input'
require './parser_netflow'

module Fluent::Plugin
  class NetflowInput < Input
    Fluent::Plugin.register_input('netflow', self)

    helpers :server

    config_param :port, :integer, default: 5140
    config_param :bind, :string, default: '0.0.0.0'
    config_param :tag, :string
    config_param :protocol_type, default: :udp do |val|
      case val.downcase
      when 'udp'
        :udp
      else
        raise Fluent::ConfigError, "netflow input protocol type should be 'udp'"
      end
    end
    config_param :max_bytes, :integer, default: 2048

    def configure(conf)
      super

      @parser = Fluent::Plugin::NetflowParser.new
      @parser.configure(conf)
    end

    def start
      super
      server_create(:in_netflow_server, @port, bind: @bind, proto: @protocol_type, max_bytes: @max_bytes) do |data, sock|
        receive_data(sock.remote_host, data)
      end
    end

    def shutdown
      super
    end

    protected

    def receive_data(host, data)
      log.on_debug { log.debug "received logs", :host => host, :data => data }

      @parser.call(data, host) { |time, record|
        unless time && record
          log.warn "pattern not match: #{data.inspect}"
          return
        end

        record['host'] = host
        router.emit(@tag, time, record)
      }
    rescue => e
      log.warn "unexpected error on parsing", data: data.dump, error_class: e.class, error: e.message
      log.warn_backtrace
    end
  end
end
