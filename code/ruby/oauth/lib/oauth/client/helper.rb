require 'oauth/client'
require 'oauth/consumer'
require 'oauth/token'
require 'oauth/signature/hmac/sha1'

module OAuth::Client
  class Helper
    def initialize(request, request_uri, consumer, token, sig_method, nonce = nil, timestamp = nil)
      @request = request
      @request_uri = request_uri
      @consumer = consumer
      @token = token
      @sig_method = sig_method
      @nonce = nonce
      @timestamp = timestamp
    end

    def nonce
      @nonce || generate_nonce
    end

    def timestamp
      @timestamp || generate_timestamp
    end

    def generate_timestamp
      Time.now.to_i.to_s
    end

    def generate_nonce
      rand(2**128).to_s
    end

    def oauth_parameters
      { 'oauth_consumer_key'     => @consumer.key,
        'oauth_token'            => @token.token,
        'oauth_signature_method' => @sig_method,
        'oauth_timestamp'        => timestamp,
        'oauth_nonce'            => nonce }
    end

    def signature(extra_options = {})
      signature = OAuth::Signature.sign(@request, { :uri      => @request_uri,
                                                    :consumer => @consumer,
                                                    :token    => @token }.merge(extra_options) )
    end

    def header
      parameters = oauth_parameters
      parameters.merge!( { 'oauth_signature' => signature( { :parameters => parameters } ) } )

      header_params_str = parameters.map { |k,v| "#{k}=\"#{v}\"" }.join(', ')

      return "OAuth #{header_params_str}"
    end

    def parameters
      OAuth::RequestProxy.proxy(@request).parameters
    end

    def parameters_with_oauth
      oauth_parameters.merge( parameters )
    end
  end
end
