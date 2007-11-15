require 'oauth/signature'
require 'oauth/request_proxy/base'
require 'base64'

module OAuth::Signature
  class Base

    def self.implements(signature_method)
      OAuth::Signature.available_methods[signature_method] = self
    end

    def initialize(request)
      @request = OAuth::RequestProxy.proxy(request)
    end

    def signature
      Base64.encode64(digest).chomp
    end

    def ==(cmp_signature)
      Base64.decode64(signature) == Base64.decode64(cmp_signature)
    end

    def signature_base_string(redact_secrets = false)
      base = [request.request.method, request.request.uri, request.parameters_for_signature]
      base.map { |v| escape(v) }.join("&")
    end

    private

    def digest
      DIGEST_CLASS.digest(signature_base_string)
    end

    def escape(value)
      CGI.escape(value.to_s).gsub("%7E", "~").gsub("+", "%20").gsub("*", "%2A")
    end
  end
end
