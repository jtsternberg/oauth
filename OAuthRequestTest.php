<?php

//require_once dirname(__FILE__) . '/../oauth-php-readonly/OAuth.php';
require_once dirname(__FILE__) . '/../OAuth.php';
require_once 'PHPUnit/Framework.php';

class OAuthRequestTest extends PHPUnit_Framework_TestCase {
	public function setUp() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_HOST'] = 'testbed';
		$_SERVER['SERVER_PORT'] = 80;
		$_SERVER['REQUEST_URI'] = '/test?foo=bar';
		$_POST = array();
		$_GET = array();
		$_SERVER['HTTP_AUTHORIZATION'] = null;
	}
	
	public function testFromRequestPost() {
		$_POST = array('foo'=>'bar', 'baz'=>'blargh');
		
		$r = OAuthRequest::from_request();
		
		$this->assertEquals('POST', $r->get_normalized_http_method());
		$this->assertEquals('http://testbed/test', $r->get_normalized_http_url());
		$this->assertEquals(array('foo'=>'bar','baz'=>'blargh'), $r->get_parameters());
	}
	
	public function testFromRequestPostGet() {
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_GET = array('foo'=>'bar', 'baz'=>'blargh');
		
		$r = OAuthRequest::from_request();
		
		$this->assertEquals('GET', $r->get_normalized_http_method());
		$this->assertEquals('http://testbed/test', $r->get_normalized_http_url());
		$this->assertEquals(array('foo'=>'bar','baz'=>'blargh'), $r->get_parameters());
	}
	
	public function testFromRequestHeader() {
		$_SERVER['HTTP_AUTHORIZATION'] = 'OAuth realm="",oauth_foo=bar,oauth_baz="bla,rgh"';
		
		$r = OAuthRequest::from_request();
		
		$this->assertEquals('POST', $r->get_normalized_http_method());
		$this->assertEquals('http://testbed/test', $r->get_normalized_http_url());
		$this->assertEquals(array('oauth_foo'=>'bar','oauth_baz'=>'bla,rgh'), $r->get_parameters(), 'Please apply split_headers.patch');
	}

	public function testNormalizeParameters() {
		unset($_SERVER['HTTP_AUTHORIZATION']);
		$_SERVER['REQUEST_METHOD'] = 'POST';
			
		$_POST = array('name'=>'');
		$r = OAuthRequest::from_request();
		$this->assertEquals( 'name=', $r->get_signable_parameters());
		
		$_POST = array('a'=>'b');
		$r = OAuthRequest::from_request();
		$this->assertEquals( 'a=b', $r->get_signable_parameters());
		
		$_POST = array('a'=>'b', 'c'=>'d');
		$r = OAuthRequest::from_request();
		$this->assertEquals( 'a=b&c=d', $r->get_signable_parameters());
		
		$_POST = array('a'=>array('x!y', 'x y'));
		$r = OAuthRequest::from_request();
		$this->assertEquals( 'a=x%20y&a=x%21y', $r->get_signable_parameters());
		
		$_POST = array('x!y'=>'a', 'x'=>'a');
		$r = OAuthRequest::from_request();
		$this->assertEquals( 'x=a&x%21y=a', $r->get_signable_parameters());
		
		$_POST = array('a'=>1, 'c'=>'hi there', 'f'=>array(25, 50, 'a'), 'z'=>array('p', 't'));
		$r = OAuthRequest::from_request();
		$this->assertEquals( 'a=1&c=hi%20there&f=25&f=50&f=a&z=p&z=t', $r->get_signable_parameters());
	}

	public function testGetBaseString() {
		$_POST = array('n'=>'v');
		$r = OAuthRequest::from_request();
		$this->assertEquals('POST&http%3A%2F%2Ftestbed%2Ftest&n%3Dv', $r->get_signature_base_string());
		
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_HOST'] = 'example.com';
		$_SERVER['REQUEST_URI'] = '';
		$_GET = array('n'=>'v');
		$r = OAuthRequest::from_request();
		$this->assertEquals('GET&http%3A%2F%2Fexample.com&n%3Dv', $r->get_signature_base_string());
		
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_HOST'] = 'photos.example.net';
		$_SERVER['REQUEST_URI'] = '/request_token';
		$_SERVER['HTTPS'] = 'on';
		$_POST = array('oauth_version'=>'1.0', 'oauth_consumer_key'=>'dpf43f3p2l4k3l03', 
					'oauth_timestamp'=>'1191242090', 'oauth_nonce'=>'hsu94j3884jdopsl',
					'oauth_signature_method'=>'PLAINTEXT', 'oauth_signature'=>'ignored');
		$r = OAuthRequest::from_request();
		$this->assertEquals('POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_'
							.'consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884j'
							.'dopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestam'
							.'p%3D1191242090%26oauth_version%3D1.0', $r->get_signature_base_string());		
							
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_HOST'] = 'photos.example.net';
		$_SERVER['REQUEST_URI'] = '/photos';
		
		unset($_SERVER['HTTPS']);
		$_GET = array('file'=>'vacation.jpg', 'size'=>'original', 'oauth_version'=>'1.0', 
					'oauth_consumer_key'=>'dpf43f3p2l4k3l03', 'oauth_token'=>'nnch734d00sl2jdk',
					'oauth_timestamp'=>'1191242096', 'oauth_nonce'=>'kllo9940pd9333jh',
					'oauth_signature'=>'ignored', 'oauth_signature_method'=>'HMAC-SHA1');
		$r = OAuthRequest::from_request();
		$this->assertEquals('GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation'
							.'.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%'
							.'3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26o'
							.'auth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jd'
							.'k%26oauth_version%3D1.0%26size%3Doriginal', $r->get_signature_base_string());
							
	}

	// We only test two entries here. This is just to test that the correct 
	// signature method is chosen. Generation of the signatures is tested 
	// elsewhere, and so is the base-string the signature build upon.
	public function testBuildSignature() {
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_HOST'] = 'photos.example.net';
		$_SERVER['REQUEST_URI'] = '/photos';
		$_GET = array('file'=>'vacation.jpg', 'size'=>'original', 'oauth_version'=>'1.0', 
					'oauth_consumer_key'=>'dpf43f3p2l4k3l03', 'oauth_token'=>'nnch734d00sl2jdk',
					'oauth_timestamp'=>'1191242096', 'oauth_nonce'=>'kllo9940pd9333jh',
					'oauth_signature'=>'ignored', 'oauth_signature_method'=>'HMAC-SHA1');
		$r = OAuthRequest::from_request();
		
		$cons = new OAuthConsumer('key', 'kd94hf93k423kf44');
		$token = new OAuthToken('token', 'pfkkdhi9sl3r4s00');
		$hmac = new OAuthSignatureMethod_HMAC_SHA1();
		$plaintext = new OAuthSignatureMethod_PLAINTEXT();
		
		$this->assertEquals('tR3+Ty81lMeYAr/Fid0kMTYa/WM=', $r->build_signature($hmac, $cons, $token));
		$this->assertEquals('kd94hf93k423kf44%26pfkkdhi9sl3r4s00', $r->build_signature($plaintext, $cons, $token));
	}


	public function testSign() {
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_HOST'] = 'photos.example.net';
		$_SERVER['REQUEST_URI'] = '/photos';
		$_GET = array('file'=>'vacation.jpg', 'size'=>'original', 'oauth_version'=>'1.0', 
					'oauth_consumer_key'=>'dpf43f3p2l4k3l03', 'oauth_token'=>'nnch734d00sl2jdk',
					'oauth_timestamp'=>'1191242096', 'oauth_nonce'=>'kllo9940pd9333jh',
					'oauth_signature'=>'ignored', 'oauth_signature_method'=>'HMAC-SHA1');
		$r = OAuthRequest::from_request();
		
		$cons = new OAuthConsumer('key', 'kd94hf93k423kf44');
		$token = new OAuthToken('token', 'pfkkdhi9sl3r4s00');
		$hmac = new OAuthSignatureMethod_HMAC_SHA1();
		$plaintext = new OAuthSignatureMethod_PLAINTEXT();
		
		$r->sign_request($hmac, $cons, $token);
		
		$params = $r->get_parameters();
		$this->assertEquals('HMAC-SHA1', $params['oauth_signature_method']);
		$this->assertEquals('tR3+Ty81lMeYAr/Fid0kMTYa/WM=', $params['oauth_signature']);
		
		$r->sign_request($plaintext, $cons, $token);
		
		$params = $r->get_parameters();
		$this->assertEquals('PLAINTEXT', $params['oauth_signature_method']);
		$this->assertEquals('kd94hf93k423kf44%26pfkkdhi9sl3r4s00', $params['oauth_signature']);
	}
}

?>