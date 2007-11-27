require 'oauth/consumer'
require 'oauth/token'
require 'oauth/signature'

module OAuth
  class Request
    attr_accessor :consumer, :token, :request, :realm, :signature_method, :nonce, :timestamp
    attr_reader :parameters_for_signature

    def initialize(consumer, token, request, request_options = {},
                   realm = '', signature_method = 'HMAC-SHA1', nonce = nil, timestamp = nil)
      @consumer = consumer
      @token ||= OAuth::Token.new('', '')
      @request = OAuth::RequestProxy.proxy(request)
      @realm = realm
      @signature_method = signature_method
      @nonce = nonce || generate_nonce
      @timestamp = timestamp || generate_timestamp
    end

    def parameters
      request_and_oauth_parameters.merge({ :oauth_signature => signature(true) })
    end

    def auth_header
      "OAuth realm=\"#{realm}\", " +
      "oauth_consumer_key=\"#{consumer.key}\", " +
      "oauth_token=\"#{token.token}\", " +
      "oauth_signature_method=\"#{signature_method}\", " +
      "oauth_signature=\"#{signature}\", " +
      "oauth_timestamp=\"#{oauth_timestamp}\", " +
      "oauth_nonce=\"#{oauth_nonce}\""
    end

    def method
      request.method
    end
    
    def uri
      request.uri
    end

    private

    def signature(include_oauth_parameters = false)
      if include_oauth_parameters
        @parameters_for_signature = request_and_oauth_parameters
      else
        @parameters_for_signature = request.parameters
      end

      OAuth::Signature.sign(self)
    end

    def oauth_parameters
      { :oauth_consumer_key     => consumer.key,
        :oauth_token            => token.token,
        :oauth_nonce            => nonce,
        :oauth_timestamp        => timestamp,
        :oauth_signature_method => signature_method }
    end

    def request_and_oauth_parameters
      request.parameters.merge(oauth_parameters)
    end

    def generate_nonce
      rand(2**128).to_s
    end

    def generate_timestamp
      Time.now.to_i.to_s
    end
  end
end
