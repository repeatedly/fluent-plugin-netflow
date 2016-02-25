require 'helper'

class NetflowParserTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
  end

  def create_parser(conf=nil)
    parser = Fluent::TextParser::NetflowParser.new
    parser.configure(conf || Fluent::Config::Element.new('ROOT', '', {}, []))
    parser
  end

  def test_configure
    assert_nothing_raised do
      parser = create_parser
    end
  end
end
