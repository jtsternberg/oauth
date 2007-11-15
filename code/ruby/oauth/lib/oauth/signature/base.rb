require 'oauth/signature'
require 'oauth/request_proxy/base'
require 'base64'

module OAuth::Signature
  class Base

    def self.implements(signature_method)
      OAuth::Signature.available_methods[signature_method] = self
    end

    def initialize(request, &block)
      @request = OAuth::RequestProxy.proxy(request)
      @token_secret, @consumer_secret = yield block.arity == 1 ? token : [token, consumer_key]
    end

    def signature
      Base64.encode64(digest).chomp
    end

    def ==(cmp_signature)
      Base64.decode64(signature) == Base64.decode64(cmp_signature)
    end

    def signature_base_string
      base = [request.request.method, request.request.uri, request.parameters_for_signature]
      base.map { |v| escape(v) }.join("&")
    end

    private

    def token
      request.token
    end
    
    def consumer_key
      request.consumer_key
    end

    def digest
      DIGEST_CLASS.digest(signature_base_string)
    end

    def escape(value)
      CGI.escape(value.to_s).gsub("%7E", "~").gsub("+", "%20").gsub("*", "%2A")
    end
  end
end
