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

require 'cool.io'
require 'fluent/plugin/input'
require 'fluent/plugin/socket_util'
require 'fluent/plugin/parser_netflow'

module Fluent::Plugin
  class NetflowInput < Input
    Fluent::Plugin.register_input('netflow', self)

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

    def configure(conf)
      super

      @parser = Fluent::Plugin::NetflowParser.new
      @parser.configure(conf)
    end

    def start
      super
      @loop = Coolio::Loop.new
      @handler = listen(method(:receive_data))
      @loop.attach(@handler)

      @thread = Thread.new(&method(:run))
    end

    def shutdown
      @loop.watchers.each { |w| w.detach }
      @loop.stop
      @handler.close
      @thread.join
      super
    end

    def run
      @loop.run
    rescue => e
      log.error "unexpected error", error_class: e.class, error: e.message
      log.error_backtrace
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

    private

    def listen(callback)
      log.info "listening netflow socket on #{@bind}:#{@port} with #{@protocol_type}"
      if @protocol_type == :udp
        @usock = SocketUtil.create_udp_socket(@bind)
        @usock.bind(@bind, @port)
        UdpHandler.new(@usock, callback)
      else
        Coolio::TCPServer.new(@bind, @port, TcpHandler, log, callback)
      end
    end

    class UdpHandler < Coolio::IO
      def initialize(io, callback)
        super(io)
        @io = io
        @callback = callback
      end

      def on_readable
        msg, addr = @io.recvfrom_nonblock(4096)
        @callback.call(addr[3], msg)
      rescue => e
        log.error "unexpected error on reading from socket", error_class: e.class, error: e.message
        log.error_backtrace
      end
    end
  end
end
