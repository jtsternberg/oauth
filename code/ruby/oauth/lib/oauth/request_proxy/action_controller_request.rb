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
        query_params.merge(header_params).merge(options[:parameters] || {})
      end
    end

    def parameters_for_signature
      parameters.dup.delete('oauth_signature')
    end

    protected

    def header_params
      %w( X-HTTP_AUTHORIZATION Authorization HTTP_AUTHORIZATION ).each do |header|
        next unless request.env.include?(header)
        next unless header[0,6] == 'OAuth '

        oauth_param_string = header[6,header.length].split(/[,=]/)
        oauth_param_string.map! { |v| unescape(v.strip) }
        oauth_params = Hash[*oauth_param_string.flatten]
        oauth_params.reject! { |k,v| k !~ /^oauth_/ }

        return oauth_params
      end

      return {}
    end

    def query_params
      request.query_parameters
    end

    def unescape(value)
      URI.unescape(value.gsub('+', '%2B'))
    end

  end
end
