require File.dirname(__FILE__) + '/test_helper.rb'
require 'oauth/consumer'

class TestConsumer < Test::Unit::TestCase

  def setup
  end
  
  def test_consumer_constructor_produces_valid_consumer
    token = OAuth::Consumer.new('xyz', '123')
    assert_equal 'xyz', token.key
    assert_equal '123', token.secret
  end
end
