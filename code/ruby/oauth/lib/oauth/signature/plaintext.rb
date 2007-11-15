require 'oauth/signature/base'

module OAuth::Signature
  class PLAINTEXT < Base
    implements 'plaintext'

    def signature
      signature_base_string
    end

    def ==(cmp_signature)
      signature == cmp_signature
    end

    def signature_base_string(redact_secrets = false)
      if redact_secrets
        "CONSUMER_SECRET&TOKEN_SECRET"
      else
        "#{escape(request.consumer.secret)}&#{escape(request.token.secret)}"
      end
    end
  end
end
