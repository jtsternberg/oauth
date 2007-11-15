require 'oauth/signature/base'
require 'digest/sha1'

module OAuth::Signature
  class SHA1 < Base
    implements 'sha1'

    DIGEST_CLASS = Digest::SHA1
  end
end
