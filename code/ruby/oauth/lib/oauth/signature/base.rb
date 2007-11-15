require 'oauth/signature'
require 'oauth/request_proxy/base'
require 'base64'

module OAuth::Signature
  class Base

    def self.implements(signature_method)
      OAuth::Signature.available_methods[signature_method] = self
    end

    def self.digest_class(digest_class = nil)
      return @digest_class if digest_class.nil?
      @digest_class = digest_class
    end

    attr_reader :token_secret, :consumer_secret

    def initialize(request, &block)
      @request = request
      @token_secret, @consumer_secret = yield block.arity == 1 ? token : [token, consumer_key]
    end

    def signature
      Base64.encode64(digest).chomp
    end

    def ==(cmp_signature)
      Base64.decode64(signature) == Base64.decode64(cmp_signature)
    end

    def verify
      self == self.request.signature
    end

    def signature_base_string
      base = [request.method, request.uri, request.parameters_for_signature]
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
      URI.escape(value.to_s).gsub("*", "%2A").gsub("+", "%2B")
    end
  end
end
