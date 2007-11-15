require 'oauth/signature/base'

module OAuth::Signature::HMAC
  class Base < OAuth::Signature::Base

    private

    def digest
      self.digest_class.digest(secret, signature_base_string)
    end

    def secret
      "#{escape(consumer_secret)}&#{escape(token_secret)}"
    end
  end
end
