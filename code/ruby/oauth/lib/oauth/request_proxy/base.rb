require 'oauth/request_proxy'

module OAuth::RequestProxy
  class Base
    def self.proxies(klass)
      OAuth::RequestProxy.available_proxies[klass] = self
    end

    attr_accessor :request, :options

    def initialize(request, options)
      @request = request
      @options = options
    end

    def token
      parameters[:oauth_token]
    end

    def consumer_key
      parameters[:oauth_consumer_key]
    end
  end
end
