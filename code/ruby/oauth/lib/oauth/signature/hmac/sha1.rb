require 'oauth/signature/hmac/base'
require 'rubygems'
require 'hmac-sha1'

module OAuth::Signature::HMAC
  class SHA1 < Base
    implements 'hmac-sha1'
    DIGEST_CLASS = ::HMAC::SHA1
  end
end
