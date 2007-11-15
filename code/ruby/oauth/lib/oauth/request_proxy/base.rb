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
  end
end
