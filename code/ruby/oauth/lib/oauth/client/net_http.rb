require 'oauth/client/helper'
require 'oauth/request_proxy/net_http'

class Net::HTTPRequest
  def oauth(oauth_method, req_uri, consumer, token, sig_method = 'HMAC-SHA1', nonce = nil, timestamp = nil)
    @oauth_helper = OAuth::Client::Helper.new(self, req_uri, consumer, token, sig_method, nonce, timestamp)
    self.send("set_oauth_#{oauth_method}")
  end

  private

  def set_oauth_header
    self['Authorization'] = @oauth_helper.header
  end

  # FIXME: if you're using a POST body and query string parameters, using this
  # method will convert those parameters on the query string into parameters in
  # the body. this is broken, and should be fixed.
  def set_oauth_body
    self.set_form_data(@oauth_helper.parameters_with_oauth)
    params_with_sig = @oauth_helper.parameters.merge(:oauth_signature => @oauth_helper.signature)
    self.set_form_data(params_with_sig)
  end

  def set_oauth_query_string
    oauth_params_str = @oauth_helper.oauth_parameters.map { |k,v| "#{k}=#{v}" }.join("&")

    uri = URI.parse(path)
    if !uri.query || uri.query == ''
      uri.query = oauth_params_str
    else
      uri.query = uri.query + "&" + oauth_params_str
    end

    @path = uri.to_s

    @path << "&oauth_signature=#{@oauth_helper.signature}"
  end
end
