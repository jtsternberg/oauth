module OAuth
  module Signature
    def self.sign(oauth_request)
      klass = case oauth_request.signature_method.downcase
      when 'md5': OAuth::Signature::MD5
      when 'sha1': OAuth::Signature::SHA1
      when 'hmac-md5': OAuth::Signature::HMAC::MD5
      when 'hmac-sha1': OAuth::Signature::HMAC::SHA1
      when 'hmac-sha2': OAuth::Signature::HMAC::SHA2
      when 'hmac-rmd160': OAuth::Signature::HMAC::RMD160
      when 'plaintext': OAuth::Signature::PLAINTEXT
      when 'rsa-sha1': OAuth::Signature::RSA::SHA1
      else
        raise UnknownSignatureMethod, oauth_request.signature_method
      end

      klass.new(oauth_request).signature
    end

    class UnknownSignatureMethod < Exception; end

    class Base
      def signature
        Base64.encode64(digest).chomp
      end

      def ==(cmp_signature)
        signature == cmp_signature
      end

      def signature_base_string(redact_secrets = false)
        base = [request.request.method, request.request.uri, request.parameters_for_signature]

        if redact_secrets
          sig_arr = base.concat(['CONSUMER_SECRET', 'TOKEN_SECRET'])
        else
          sig_arr = base.concat([request.consumer.secret, request.token.secret])
        end

        sig_arr.map { |v| escape(v) }.join("&")
      end

      private

      def digest
        digest_class.digest(signature_base_string)
      end
    end

    class MD5 < Base
      private
      def digest_class; Digest::MD5; end
    end

    class SHA1 < Base
      private
      def digest_class; Digest::SHA1; end
    end

    class PLAINTEXT < Base

      def signature
        signature_base_string
      end

      def signature_base_string(redact_secrets = false)
        if redact_secrets
          "CONSUMER_SECRET&TOKEN_SECRET"
        else
          "#{escape(request.consumer.secret)}&#{escape(request.token.secret)}"
        end
      end

      private

      def digest; signature_base_string; end
    end

    module HMAC
      class Base < OAuth::Signature::Base

        private

        def digest
          hmac_class.digest(secret, signature_base_string)
        end

        def secret
          "#{escape(request.consumer.secret)}&#{escape(request.token.secret)}"
        end
      end

      class MD5 < Base
        private
        def hmac_class; HMAC::MD5; end
      end

      class RMD160 < Base
        private
        def hmac_class; HMAC::RMD160; end
      end

      class SHA1 < Base
        private
        def hmac_class; HMAC::SHA1; end
      end

      class SHA2 < Base
        private
        def hmac_class; HMAC::SHA1; end
      end
    end

    module RSA
      class SHA1 < OAuth::Signature::Base
        def ==(cmp_signature)
          public_key = OpenSSL::PKey::RSA.new(request.consumer.secret)
          public_key.verify(OpenSSL::Digest::SHA1.new, cmp_signature, signature_base_string)
        end

        private

        def digest
          private_key = OpenSSL::PKey::RSA.new(request.consumer.secret)
          private_key.sign(OpenSSL::Digest::SHA1.new, signature_base_string)
        end
      end
    end
  end
end
