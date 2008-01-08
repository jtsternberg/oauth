require 'test/unit'
require 'oauth/consumer'

# This performs testing against Andy Smith's test server http://term.ie/oauth/example/
# Thanks Andy.
# This also means you have to be online to be able to run these.
class ConsumerTest < Test::Unit::TestCase
  def setup
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
    
  end
  
  def test_initializer
    assert_equal "key",@consumer.key
    assert_equal "secret",@consumer.secret
    assert_equal "http://term.ie",@consumer.site
    assert_equal "/oauth/example/request_token.php",@consumer.request_token_path
    assert_equal "/oauth/example/access_token.php",@consumer.access_token_path
    assert_equal "http://term.ie/oauth/example/request_token.php",@consumer.request_token_url
    assert_equal "http://term.ie/oauth/example/access_token.php",@consumer.access_token_url
    assert_equal "http://term.ie/oauth/example/authorize.php",@consumer.authorize_url
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

  #TODO REWRITE THESE  
  def test_create_request
    response=@consumer.token_request :get,'/oauth/example/request_token.php'
    assert "requestkey",response[:oauth_token]
  end
  
  def test_create_post_request
    response=@consumer.request(:post,'/oauth/example',@token,{},"BODY")
  end

  def test_create_put_request
    response=@consumer.request(:put,'/oauth/example',@token,{},"BODY")
#    assert_equal "token",request['oauth_token']
#    assert "key",request['consumer_key']
#    assert_equal "BODY",request.body
  end
  
  def test_get_token_sequence
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
end
