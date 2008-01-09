require 'test/unit'
require 'oauth/consumer'

# This performs testing against Andy Smith's test server http://term.ie/oauth/example/
# Thanks Andy.
# This also means you have to be online to be able to run these.
class ConsumerTest < Test::Unit::TestCase
  def setup
    @consumer=OAuth::Consumer.new( 
        'consumer_key_86cad9', '5888bf0345e5d237',
        {
        :site=>"http://blabla.bla",
        :request_token_path=>"/oauth/example/request_token.php",
        :access_token_path=>"/oauth/example/access_token.php",
        :authorize_path=>"/oauth/example/authorize.php",
        :auth_method=>:query,
        :http_method=>:get
        })
    @token = OAuth::ConsumerToken.new(@consumer,'token_411a7f', '3196ffd991c8ebdb')
    @request_uri = URI.parse('http://example.com/test?key=value')
    @request_parameters = { 'key' => 'value' }
    @nonce = 225579211881198842005988698334675835446
    @timestamp = "1199645624"
    @consumer.http=Net::HTTP.new(@request_uri.host, @request_uri.port)
  end
  
  def test_initializer
    assert_equal "consumer_key_86cad9",@consumer.key
    assert_equal "5888bf0345e5d237",@consumer.secret
    assert_equal "http://blabla.bla",@consumer.site
    assert_equal "/oauth/example/request_token.php",@consumer.request_token_path
    assert_equal "/oauth/example/access_token.php",@consumer.access_token_path
    assert_equal "http://blabla.bla/oauth/example/request_token.php",@consumer.request_token_url
    assert_equal "http://blabla.bla/oauth/example/access_token.php",@consumer.access_token_url
    assert_equal "http://blabla.bla/oauth/example/authorize.php",@consumer.authorize_url
    assert_equal :query,@consumer.auth_method
    assert_equal :get,@consumer.http_method
  end

  def test_defaults
    @consumer=OAuth::Consumer.new(
      "key",
      "secret",
      {
          :site=>"http://twitter.com"
      })
    assert_equal "key",@consumer.key
    assert_equal "secret",@consumer.secret
    assert_equal "http://twitter.com",@consumer.site
    assert_equal "/oauth/request_token",@consumer.request_token_path
    assert_equal "/oauth/access_token",@consumer.access_token_path
    assert_equal "http://twitter.com/oauth/request_token",@consumer.request_token_url
    assert_equal "http://twitter.com/oauth/access_token",@consumer.access_token_url
    assert_equal "http://twitter.com/oauth/authorize",@consumer.authorize_url
    assert_equal :authorize,@consumer.auth_method
    assert_equal :post,@consumer.http_method 
  end

  def test_override_paths
    @consumer=OAuth::Consumer.new(
      "key",
      "secret",
      {
          :site=>"http://twitter.com",
          :request_token_url=>"http://oauth.twitter.com/request_token",
          :access_token_url=>"http://oauth.twitter.com/access_token",
          :authorize_url=>"http://site.twitter.com/authorize"
      })
    assert_equal "key",@consumer.key
    assert_equal "secret",@consumer.secret
    assert_equal "http://twitter.com",@consumer.site
    assert_equal "/oauth/request_token",@consumer.request_token_path
    assert_equal "/oauth/access_token",@consumer.access_token_path
    assert_equal "http://oauth.twitter.com/request_token",@consumer.request_token_url
    assert_equal "http://oauth.twitter.com/access_token",@consumer.access_token_url
    assert_equal "http://site.twitter.com/authorize",@consumer.authorize_url
    assert_equal :authorize,@consumer.auth_method
    assert_equal :post,@consumer.http_method 
  end

  def test_that_using_auth_headers_on_get_requests_works
    request = Net::HTTP::Get.new(@request_uri.path + "?" + request_parameters_to_s)
    @token.sign!(request, {:nonce => @nonce, :timestamp => @timestamp})
    
    assert_equal 'GET', request.method
    assert_equal '/test?key=value', request.path
    assert_equal "OAuth oauth_nonce=\"225579211881198842005988698334675835446\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"token_411a7f\", oauth_timestamp=\"1199645624\", oauth_consumer_key=\"consumer_key_86cad9\", oauth_signature=\"ivvLU8Cs45JjuFNMsE13eMl7pAc=\"", request['authorization']
  end

  def test_that_using_auth_headers_on_post_requests_works
    request = Net::HTTP::Post.new(@request_uri.path)
    request.set_form_data( @request_parameters )
    @token.sign!(request, {:nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'POST', request.method
    assert_equal '/test', request.path
    assert_equal 'key=value', request.body
    assert_equal "OAuth oauth_nonce=\"225579211881198842005988698334675835446\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"token_411a7f\", oauth_timestamp=\"1199645624\", oauth_consumer_key=\"consumer_key_86cad9\", oauth_signature=\"iMZaUTbQof/HMFyIde+OIkhW5is=\"", request['authorization']
  end
 
  def test_that_using_post_params_works
    request = Net::HTTP::Post.new(@request_uri.path)
    request.set_form_data( @request_parameters )
    @token.sign!(request, {:scheme => 'body', :nonce => @nonce, :timestamp => @timestamp})

    assert_equal 'POST', request.method
    assert_equal '/test', request.path
    assert_equal "key=value&oauth_consumer_key=consumer_key_86cad9&oauth_nonce=225579211881198842005988698334675835446&oauth_signature=iMZaUTbQof%2fHMFyIde%2bOIkhW5is%3d&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1199645624&oauth_token=token_411a7f", request.body.split("&").sort.join("&")
    assert_equal nil, request['authorization']
  end
  
  def test_get_token_sequence
    
    @consumer=OAuth::Consumer.new( 
        "key",
        "secret",
        {
        :site=>"http://term.ie",
        :request_token_path=>"/oauth/example/request_token.php",
        :access_token_path=>"/oauth/example/access_token.php",
        :authorize_path=>"/oauth/example/authorize.php",
        :auth_method=>:query,
        :http_method=>:get
        })
    @token=OAuth::Token.new "token","token_secret"
    
    
    @request_token=@consumer.get_request_token
    assert_not_nil @request_token
    assert_equal "requestkey",@request_token.token
    assert_equal "requestsecret",@request_token.secret
    assert_equal "http://term.ie/oauth/example/authorize.php?oauth_token=requestkey",@request_token.authorize_url

    @access_token=@request_token.get_access_token
    assert_not_nil @access_token
    assert_equal "accesskey",@access_token.token
    assert_equal "accesssecret",@access_token.secret
    
    @response=@access_token.get("/oauth/example/echo_api.php?ok=hello&test=this")
    assert_not_nil @response
    assert_equal "200",@response.code
    assert_equal( "ok=hello&test=this",@response.body)
    
    @response=@access_token.post("/oauth/example/echo_api.php","ok=hello&test=this")
    assert_not_nil @response
    assert_equal "200",@response.code
    assert_equal( "ok=hello&test=this",@response.body)    
  end
  protected

  def request_parameters_to_s
    @request_parameters.map { |k,v| "#{k}=#{v}" }.join("&")
  end

  
end

