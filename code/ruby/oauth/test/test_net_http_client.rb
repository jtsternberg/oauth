require File.dirname(__FILE__) + '/test_helper.rb'
require 'oauth/client/net_http'

class NetHTTPClientTest < Test::Unit::TestCase

  def setup
    @consumer = OAuth::Consumer.new('consumer_key_86cad9', '5888bf0345e5d237')
    @token = OAuth::Token.new('token_411a7f', '3196ffd991c8ebdb')
    @request_uri = URI.parse('http://example.com/test?key=value')
    @request_parameters = { 'key' => 'value' }
    @nonce = 225579211881198842005988698334675835446
    @timestamp = "1199645624"
    @http = Net::HTTP.new(@request_uri.host, @request_uri.port)
  end

  def test_that_using_auth_headers_on_get_requests_works
    request = Net::HTTP::Get.new(@request_uri.path + "?" + request_parameters_to_s)
    request.oauth!(@http, @consumer, @token, {:nonce => @nonce, :timestamp => @timestamp})
    
    assert_equal 'GET', request.method
    assert_equal '/test?key=value', request.path
    assert_equal "OAuth oauth_nonce=\"225579211881198842005988698334675835446\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"token_411a7f\", oauth_timestamp=\"1199645624\", oauth_consumer_key=\"consumer_key_86cad9\", oauth_signature=\"ivvLU8Cs45JjuFNMsE13eMl7pAc=\"", request['authorization']
  end

  def test_that_using_auth_headers_on_post_requests_works
    request = Net::HTTP::Post.new(@request_uri.path)
    request.set_form_data( @request_parameters )
    request.oauth!(@http, @consumer, @token, {:nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'POST', request.method
    assert_equal '/test', request.path
    assert_equal 'key=value', request.body
    assert_equal "OAuth oauth_nonce=\"225579211881198842005988698334675835446\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"token_411a7f\", oauth_timestamp=\"1199645624\", oauth_consumer_key=\"consumer_key_86cad9\", oauth_signature=\"iMZaUTbQof/HMFyIde+OIkhW5is=\"", request['authorization']
  end
 
  def test_that_using_post_params_works
    request = Net::HTTP::Post.new(@request_uri.path)
    request.set_form_data( @request_parameters )
    request.oauth!(@http, @consumer, @token, {:scheme => 'body', :nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'POST', request.method
    assert_equal '/test', request.path
    assert_equal "key=value&oauth_consumer_key=consumer_key_86cad9&oauth_nonce=225579211881198842005988698334675835446&oauth_signature=iMZaUTbQof%2fHMFyIde%2bOIkhW5is%3d&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1199645624&oauth_token=token_411a7f", request.body.split("&").sort.join("&")
    assert_equal nil, request['authorization']
  end

  def test_that_using_get_params_works
    request = Net::HTTP::Get.new(@request_uri.path + "?" + request_parameters_to_s)
    request.oauth!(@http, @consumer, @token, {:scheme => 'query_string', :nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'GET', request.method
    uri = URI.parse(request.path)
    assert_equal '/test', uri.path
    assert_equal nil, uri.fragment
    assert_equal "key=value&oauth_consumer_key=consumer_key_86cad9&oauth_nonce=225579211881198842005988698334675835446&oauth_signature=ivvLU8Cs45JjuFNMsE13eMl7pAc=&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1199645624&oauth_token=token_411a7f", uri.query.split("&").sort.join("&")
    assert_equal nil, request['authorization']
  end

  def test_that_using_get_params_works_with_post_requests
    request = Net::HTTP::Post.new(@request_uri.path + "?" + request_parameters_to_s)
    request.oauth!(@http, @consumer, @token, {:scheme => 'query_string', :nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'POST', request.method
    uri = URI.parse(request.path)
    assert_equal '/test', uri.path
    assert_equal nil, uri.fragment
    assert_equal "key=value&oauth_consumer_key=consumer_key_86cad9&oauth_nonce=225579211881198842005988698334675835446&oauth_signature=iMZaUTbQof/HMFyIde+OIkhW5is=&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1199645624&oauth_token=token_411a7f", uri.query.split("&").sort.join('&')
    assert_equal nil, request.body
    assert_equal nil, request['authorization']
  end

  def test_that_using_get_params_works_with_post_requests_that_have_post_bodies
    request = Net::HTTP::Post.new(@request_uri.path + "?" + request_parameters_to_s)
    request.set_form_data( { 'key2' => 'value2' } )
    request.oauth!(@http, @consumer, @token, {:scheme => :query_string, :nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'POST', request.method
    uri = URI.parse(request.path)
    assert_equal '/test', uri.path
    assert_equal nil, uri.fragment
    assert_equal "key=value&oauth_consumer_key=consumer_key_86cad9&oauth_nonce=225579211881198842005988698334675835446&oauth_signature=VfqWmKpm0C9rQX918ubc6BCzILw=&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1199645624&oauth_token=token_411a7f", uri.query.split("&").sort.join('&')
    assert_equal "key2=value2", request.body
    assert_equal nil, request['authorization']
  end

  protected

    def request_parameters_to_s
      @request_parameters.map { |k,v| "#{k}=#{v}" }.join("&")
    end

end
