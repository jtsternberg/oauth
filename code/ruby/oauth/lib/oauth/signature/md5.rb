require 'oauth/signature/base'
require 'digest/md5'

module OAuth::Signature
  class MD5 < Base
    implements 'md5'

    DIGEST_CLASS = Digest::MD5
  end
end
