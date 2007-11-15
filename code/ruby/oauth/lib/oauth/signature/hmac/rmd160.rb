require 'oauth/signature/hmac/base'
require 'hmac-rmd160'

module OAuth::Signature::HMAC
  class RMD160 < Base
    implements 'hmac-rmd160'
    DIGEST_CLASS = ::HMAC::RMD160
  end
end
