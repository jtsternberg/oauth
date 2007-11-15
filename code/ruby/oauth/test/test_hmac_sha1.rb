require File.dirname(__FILE__) + '/test_helper.rb'
require 'oauth/signature/hmac/sha1'

class TestSignatureHmacSha1 < Test::Unit::TestCase
  def test_that_hmac_sha1_implements_hmac_sha1
    assert OAuth::Signature.available_methods.include?('hmac-sha1')
  end
end
