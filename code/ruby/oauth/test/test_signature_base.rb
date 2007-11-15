require File.dirname(__FILE__) + '/test_helper.rb'
require 'oauth/signature/base'

class SignatureBaseTest < Test::Unit::TestCase

  def test_that_initialize_requires_one_request_argument
    assert_raises ArgumentError do
      OAuth::Signature::Base.new()
    end
  end

  def test_that_initialize_requires_a_valid_request_argument
    request = nil
    assert_raises OAuth::RequestProxy::UnknownRequestType do
      OAuth::Signature::Base.new(request)
    end
  end

  def test_that_initialize_succeeds_when_the_request_proxy_is_valid
    # this isn't quite valid, but it will do.
    request = OAuth::RequestProxy::Base.new(nil, nil)
    assert_nothing_raised do
      OAuth::Signature::Base.new(request)
    end
  end

end
