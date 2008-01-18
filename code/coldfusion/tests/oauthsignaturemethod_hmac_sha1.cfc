<!---  
Description: 
============
	oauth.oauthsignaturemethod_hmac_sha1 testcase

License:
============
Copyright 2008 CONTENS Software GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--->
<cfcomponent 
	name="oauth.oauthsignaturemethod_hmac_sha1 testcase" 
	extends="cfcunit.framework.TestCase" 
	output="false" 
	hint="oauth.oauthsignaturemethod_hmac_sha1 testcase">
	
	<cffunction name="setUp" returntype="void" access="private" output="false" hint="test fixture">
		<cfset variables.oSigMethod = CreateObject("component", "oauth.oauthsignaturemethod_hmac_sha1")>
		
		<cfset variables.sConsumerKey = "ckey">
		<cfset variables.sConsumerSecret = "csecret">
		<cfset variables.oConsumer = CreateObject("component", "oauth.oauthconsumer").init(
					sKey = variables.sConsumerKey, 
					sSecret = variables.sConsumerSecret) >
		
		<cfset variables.sTokenKey = "tkey">
		<cfset variables.sTokenSecret = "tsecret">
		<cfset variables.oToken = CreateObject("component", "oauth.oauthtoken").init(
					sKey = variables.sTokenKey, 
					sSecret = variables.sTokenSecret) >
					
		<cfset variables.oRequest = CreateObject("component", "oauth.oauthrequest").init(
					sHttpMethod = "GET",
					sHttpURL = "http://example.com")>
		<cfset variables.oRequest.signRequest(variables.oSigMethod, variables.oConsumer, variables.oToken)>
	</cffunction>
	
	<!--------------------------------------------------------------->
	
	
	<cffunction name="testhmac" returntype="void" access="public" output="false">
		<cfset var sTemp = variables.oSigMethod.hmac(data = variables.sConsumerKey, key = variables.sConsumerSecret) >
		<cfset var sExpected = "2F16F2A7517FC08E6334C24856294068">
		<cfset assertEqualsString(sExpected, sTemp) >
	</cffunction>
	
	<cffunction name="testripemd_160" returntype="void" access="public" output="false">
		<cfset var sTemp = variables.oSigMethod.ripemd_160(msg = variables.sConsumerKey) >
		<cfset var sExpected = "BAB3F110610A00478D27910951E0C296FB3E7DE5">
		<cfset assertEqualsString(sExpected, sTemp) >
	</cffunction>
	
	<cffunction name="testbuildSignature" returntype="void" access="public" output="false">
		<cfset var sTemp = variables.oSigMethod.buildSignature(
							oRequest = variables.oRequest,
							oConsumer = variables.oConsumer,
							oToken = variables.oToken) >
		<cfset var sReqTemp = variables.oRequest.getParameter("oauth_signature")>
		<cfset assertEqualsString(sTemp, sReqTemp) >
	</cffunction>
	
	<cffunction name="testmd5" returntype="void" access="public" output="false">
		<cfset var sTemp = variables.oSigMethod.md5(msg = variables.sConsumerKey) >
		<cfset var sExpected = "65E6A8589452D9E615D96BF71DED510E">
		<cfset assertEqualsString(sExpected, sTemp) >
	</cffunction>
	
	<cffunction name="testgetName" returntype="void" access="public" output="false">
		<cfset assertEqualsString("HMAC-SHA1", variables.oSigMethod.getName())>
	</cffunction>
	
	<cffunction name="testsha_1" returntype="void" access="public" output="false">
		<cfset var sTemp = variables.oSigMethod.sha_1(msg = variables.sConsumerKey) >
		<cfset var sExpected = "237C109BC098A408041769CD96E09CAC9F796130">
		<cfset assertEqualsString(sExpected, sTemp) >
	</cffunction>
	
	<cffunction name="testsha_256" returntype="void" access="public" output="false">
		<cfset var sTemp = variables.oSigMethod.sha_256(msg = variables.sConsumerKey) >
		<cfset var sExpected = "1F1E6849B01CAC816F71BB96AF43DA4F98775E69704548B64F450C7875A564E5">
		<cfset assertEqualsString(sExpected, sTemp) >
	</cffunction>
	
	
	<!--------------------------------------------------------------->
	
	<cffunction name="tearDown" returntype="void" access="private" output="false" 
		hint="Tears down the fixture, for example, close a network connection.">
	</cffunction>
	
</cfcomponent>