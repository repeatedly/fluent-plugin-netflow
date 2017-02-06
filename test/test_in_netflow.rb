require 'helper'
require 'fluent/test/driver/input'

class NetflowInputTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
  end

  PORT = unused_port
  CONFIG = %[
    port #{PORT}
    bind 127.0.0.1
    tag  test.netflow
  ]

  def create_driver(conf=CONFIG)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::NetflowInput).configure(conf)
  end

  def test_configure
    d = create_driver
    assert_equal PORT, d.instance.port
    assert_equal '127.0.0.1', d.instance.bind
    assert_equal 'test.netflow', d.instance.tag
    assert_equal :udp, d.instance.protocol_type

    assert_raise Fluent::ConfigError do
      d = create_driver CONFIG + %[
        protocol_type tcp
      ]
    end
  end
end
