require 'oauth/signature/base'

module OAuth::Signature::HMAC
  class Base < OAuth::Signature::Base

    private

    def digest
      DIGEST_CLASS.digest(secret, signature_base_string)
    end

    def secret
      "#{escape(request.consumer.secret)}&#{escape(request.token.secret)}"
    end
  end
end
