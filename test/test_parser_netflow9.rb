require 'helper'

class Netflow9ParserTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
  end

  def create_parser(conf={})
    parser = Fluent::TextParser::NetflowParser.new
    parser.configure(Fluent::Config::Element.new('ROOT', '', conf, []))
    parser
  end

  def raw_template
    @raw_template ||= File.read(File.expand_path('../dump/netflow.v9.template.dump', __FILE__))
  end

  def raw_data
    @raw_data ||= File.read(File.expand_path('../dump/netflow.v9.dump', __FILE__))
  end

  def raw_sampler_template
    @raw_sampler_template ||= File.read(File.expand_path('../dump/netflow.v9.sampler_template.dump', __FILE__))
  end

  def raw_sampler_data
    @raw_sampler_data ||= File.read(File.expand_path('../dump/netflow.v9.sampler.dump', __FILE__))
  end

  DEFAULT_HOST = '127.0.0.1'

  test 'parse netflow v9 binary data before loading corresponding template' do
    parser = create_parser

    assert_equal 92, raw_data.size
    parser.call(raw_data, DEFAULT_HOST) do |time, record|
      assert false, 'nothing emitted'
    end
  end

  test 'parse netflow v9 binary data' do
    parser = create_parser

    parsed = []
    parser.call raw_template, DEFAULT_HOST
    parser.call(raw_data, DEFAULT_HOST) do |time, record|
      parsed << [time, record]
    end

    assert_equal 1, parsed.size
    assert_equal Time.parse('2016-02-12T04:02:25Z').to_i, parsed.first[0]
    expected_record = {
      # header
      'version'      => 9,
      'flow_seq_num' => 4645895,
      'flowset_id'   => 260,

      # flowset
      'in_pkts'           => 1,
      'in_bytes'          => 60,
      'ipv4_src_addr'     => '192.168.0.1',
      'ipv4_dst_addr'     => '192.168.0.2',
      'input_snmp'        => 54,
      'output_snmp'       => 29,
      'last_switched'     => '2016-02-12T04:02:09.053Z',
      'first_switched'    => '2016-02-12T04:02:09.053Z',
      'l4_src_port'       => 80,
      'l4_dst_port'       => 32822,
      'src_as'            => 0,
      'dst_as'            => 65000,
      'bgp_ipv4_next_hop' => '192.168.0.3',
      'src_mask'          => 24,
      'dst_mask'          => 24,
      'protocol'          => 6,
      'tcp_flags'         => 0x12,
      'src_tos'           => 0x0,
      'direction'         => 0,
      'forwarding_status' => 0b01000000,
      'flow_sampler_id'   => 1,
      'ingress_vrf_id'    => 1610612736,
      'egress_vrf_id'     => 1610612736
    }
    assert_equal expected_record, parsed.first[1]
  end

  test 'parse netflow v9 binary data after sampler data is cached' do
    parser = create_parser

    parsed = []
    [raw_sampler_template, raw_sampler_data, raw_template].each {|raw| parser.call(raw, DEFAULT_HOST){} }
    parser.call(raw_data, DEFAULT_HOST) do |time, record|
      parsed << [time, record]
    end

    assert_equal 2,    parsed.first[1]['sampling_algorithm']
    assert_equal 5000, parsed.first[1]['sampling_interval']
  end

  test 'parse netflow v9 binary data with host-based template cache' do
    parser = create_parser
    another_host = DEFAULT_HOST.next

    parsed = []
    parser.call raw_template, DEFAULT_HOST
    parser.call(raw_data, another_host) do |time, record|
      assert false, 'nothing emitted'
    end
    parser.call raw_template, another_host
    parser.call(raw_data, another_host) do |time, record|
      parsed << [time, record]
    end

    assert_equal 1, parsed.size
  end

  test 'parse netflow v9 binary data with host-based sampler cache' do
    parser = create_parser
    another_host = DEFAULT_HOST.next

    parsed = []
    [raw_sampler_template, raw_sampler_data, raw_template].each {|raw| parser.call(raw, DEFAULT_HOST){} }
    parser.call(raw_template, another_host){}
    parser.call(raw_data, another_host) do |time, record|
      parsed << [time, record]
    end

    assert_equal nil, parsed.first[1]['sampling_algorithm']
    assert_equal nil, parsed.first[1]['sampling_interval']
  end
end
