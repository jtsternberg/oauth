require 'rubygems'
require 'active_support'
require 'action_controller/request'
require 'oauth/request_proxy/base'
require 'uri'

module OAuth::RequestProxy
  class ActionControllerRequest < OAuth::RequestProxy::Base
    proxies ActionController::AbstractRequest

    def method
      request.method.to_s.upcase
    end

    def uri
      uri = URI.parse(request.protocol + request.host + request.port_string + request.path)
      uri.query = nil
      uri.to_s
    end

    def parameters
      if options[:clobber_request]
        options[:parameters] || {}
      else
        request.request_parameters.dup.merge(options[:parameters])
      end
    end
  end
end
