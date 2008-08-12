<!---
$HeadURL$
$Id$
Description:
============
	OAuth request

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

History:
============
08/12/08 - Chris Blackwell: changed generateTimestamp()
	use CreateObject("java", "java.util.Date").getTime() instead of getTickCount (OpenBlueDragon compatibility)
--->

<cfcomponent displayname="OAuthRequest">

	<cfset variables.sHttpMethod = "">
	<cfset variables.sHttpURL = "">
	<cfset variables.stParameters = StructNew()>
	<cfset variables.sOAuthVersion = "">

	<cffunction name="init" returntype="OAuthRequest" output="false">
		<cfargument name="sHttpMethod"	required="true" 	type="string" hint="request method">
		<cfargument name="sHttpURL"		required="true" 	type="string" hint="request URL">
		<cfargument name="stParameters"	required="false" 	type="struct" hint="request parameters"	default="#StructNew()#">
		<cfargument name="sOAuthVersion" required="false"	type="string" hint="OAuth protocol version" default="1.0">

		<cfset setHttpMethod(arguments.sHttpMethod)>
    	<cfset setHttpURL(arguments.sHttpURL)>
		<cfset setParameters(arguments.stParameters)>
		<cfset setVersion(arguments.sOAuthVersion)>

		<cfset StructInsert(variables.stParameters, "oauth_version", variables.sOAuthVersion, "true")>

		<cfreturn this>
	</cffunction>

	<cffunction name="getHttpMethod" access="public" returntype="string">
		<cfreturn variables.sHttpMethod>
	</cffunction>
	<cffunction name="setHttpMethod" access="public" returntype="void">
		<cfargument name="sHttpMethod" type="string" required="yes">
		<cfset variables.sHttpMethod = arguments.sHttpMethod>
	</cffunction>

	<cffunction name="getHttpURL" access="public" returntype="string">
		<cfreturn variables.sHttpURL>
	</cffunction>
	<cffunction name="setHttpURL" access="public" returntype="void">
		<cfargument name="sHttpURL" type="string" required="yes">
		<cfset variables.sHttpURL = arguments.sHttpURL>
	</cffunction>

	<cffunction name="getParameters" access="public" returntype="struct">
		<cfreturn variables.stParameters>
	</cffunction>
	<cffunction name="setParameters" access="public" returntype="void">
		<cfargument name="stParameters" type="struct" required="yes">
		<cfset variables.stParameters = arguments.stParameters>
	</cffunction>

	<cffunction name="getVersion" access="public" returntype="string" hint="version">
		<cfreturn variables.sOAuthVersion>
	</cffunction>
	<cffunction name="setVersion" access="public" returntype="void">
		<cfargument name="sOAuthVersion" type="string" required="yes">
		<cfset variables.sOAuthVersion = arguments.sOAuthVersion>
	</cffunction>

	<cffunction name="isEmpty" access="public" returntype="boolean">
		<cfset var bResult = false>
		<cfif Len(getHttpMethod()) IS 0 AND Len(getHttpURL()) IS 0>
			<cfset bResult = true>
		</cfif>
		<cfreturn bResult>
	</cffunction>

	<cffunction name="createEmptyRequest" returntype="OAuthRequest" access="public">
		<cfset var oResult = init(sHttpMethod = "", sHttpURL = "")>
		<cfreturn oResult>
	</cffunction>

	<!--- attempt to build up a request from what was passed to the server --->
	<cffunction name="fromRequest" access="public" returntype="OAuthRequest" >
		<cfargument name="sHttpMethod"		required="false" type="string" default="">
		<cfargument name="sHttpURL" 		required="false" type="string" default="">
		<cfargument name="stParameters" 	required="false" type="struct" default="#StructNew()#"/>

		<cfset var stRequestHeaders = StructNew()>
		<cfset var oResultRequest = 0>
		<cfset var stHeaderParameters = StructNew()>
		<cfset var stRequestParameters = StructNew()>
		<cfset var stTempParameters = StructNew()>

		<cfif Len(arguments.sHttpMethod) IS 0>
    		<cfset variables.sHttpMethod = cgi.request_method>
		<cfelse>
			<cfset variables.sHttpMethod = arguments.sHttpMethod>
		</cfif>

		<cfif Len(arguments.sHttpURL) IS 0>
			<cfset variables.sHttpURL = "http://" & cgi.http_host & cgi.path_info>
		<cfelse>			
			<cfset variables.sHttpURL = arguments.sHttpURL>
		</cfif>    		
	    <!--- get Authorization: header --->
    	<cfset stRequestHeaders = GetHttpRequestData().headers>

	    <!--- let the library user override things however they'd like, if they know
	    	which parameters to use then go for it, for example XMLRPC might want to do this --->
		<cfif NOT StructIsEmpty(arguments.stParameters)>
			<cfset oResultRequest = CreateObject("component", "OAuthRequest").init(
				sHttpMethod = variables.sHttpMethod, 
				sHttpURL = variables.sHttpURL, 
				stParameters = variables.stParameters)>
    
	    <!--- next check for the auth header, we need to do some extra stuff
		    if that is the case, namely suck in the parameters from GET or POST
		    so that we can include them in the signature --->
	    <cfelseif StructKeyExists(stRequestHeaders, "Authorization") AND 
		  Left(StructFind(stRequestHeaders, "Authorization"), 5) EQ "OAuth">
			<cfset stHeaderParameters = splitHeader(StructFind(stRequestHeaders, "Authorization"))>

			<cfif variables.sHttpMethod EQ "GET">
				<cfset stRequestParameters = URL>
			<cfelseif variables.sHttpMethod EQ "POST">
				<cfset stRequestParameters = FORM>
			</cfif>

			<cfset stTempParameters = stRequestParameters>
			<cfset StructAppend(stTempParameters, stHeaderParameters)> 
			<cfset StructAppend(stTempParameters, stRequestParameters)>
			<cfset oResultRequest = CreateObject("component","OAuthRequest").init(
				sHttpMethod = variables.sHttpMethod, 
				sHttpURL = variableshttpURL, 
				stParamaters = stTempParameters)>

		<cfelseif variables.sHttpMethod EQ "GET">
    		<cfset oResultRequest = CreateObject("component","OAuthRequest").init(
				sHttpMethod = variables.sHttpMethod, 
				sHttpURL = variables.sHttpURL, 
				stParameters = URL)>    
		<cfelseif variables.sHttpMethod EQ "POST">
    		<cfset oResultRequest = CreateObject("component","OAuthRequest").init(
				sHttpMethod = variables.sHttpMethod, 
				sHttpURL = variables.sHttpURL, 
				stParameters = FORM)>
		</cfif>

		<cfreturn oResultRequest>		
	</cffunction>

	<!--- helper function to set up the request --->
	<cffunction name="fromConsumerAndToken" access="public" returntype="OAuthRequest">
		<cfargument name="oConsumer"	required="true" type="OAuthConsumer">
		<cfargument name="oToken" 		required="true" type="OAuthToken">
		<cfargument name="sHttpMethod" 	required="true" type="string">
		<cfargument name="sHttpURL" 	required="true"	type="string">
		<cfargument name="stParameters"	required="false" type="struct" default="#StructNew()#">

		<cfset var oResultRequest = createEmptyRequest()>
		<cfset var stNewParameters = StructNew()>
		<cfset var stDefault = StructNew()>

		<cfset stDefault["oauth_version"] = getVersion()>
		<cfset stDefault["oauth_nonce"] = generateNonce()>
		<cfset stDefault["oauth_timestamp"] = generateTimestamp()>
		<cfset stDefault["oauth_consumer_key"] = arguments.oConsumer.getKey()>

		<cfset stNewParameters = arguments.stParameters>
		<cfset StructAppend(stNewParameters, stDefault, "yes")>

		<cfif NOT arguments.oToken.isEmpty()>
			<cfset stNewParameters["oauth_token"] = arguments.oToken.getKey()>
		</cfif>

		<cfset oResultRequest = CreateObject("component", "OAuthRequest").init(
			sHttpMethod = arguments.sHttpMethod, 
			sHttpURL = arguments.sHttpURL, 
			stParameters = stNewParameters)>
		<cfreturn oResultRequest>
	</cffunction>

 	<cffunction name="getParameter" access="public" returntype="any" hint="retrieves paramater value">
		<cfargument name="sParameterName" 	type="string"	required="true"	hint="parameter name (struct key)">
		<cfset var oResult = "">

		<cfif StructKeyExists(variables.stParameters, arguments.sParameterName)>
			<cfset oResult = StructFind(variables.stParameters, arguments.sParameterName)>
		</cfif>
		<cfreturn oResult>
	</cffunction>

	<cffunction name="setParameter" access="public" returntype="void" hint="sets parameter value">
		<cfargument name="sParameterName" 	type="string"	required="true" 	hint="paramater name (struct key)"/>
		<cfargument name="oParameterValue" 	type="any" 		required="true" 	hint="parameter value">

		<cfset StructInsert(variables.stParameters, arguments.sParameterName, arguments.oParameterValue, "true")>
	</cffunction>

	<cffunction name="getNormalizedHttpMethod" access="public" returntype="string">
		<cfreturn UCase(variables.sHttpMethod)>
	</cffunction>

   <!--- parses the url and rebuilds it to be [scheme://host/path] --->
	<cffunction name="getNormalizedHttpURL" access="public" returntype="string" output="false">
		<cfargument name="sScheme" type="string" required="false" default="http://">
		<cfset var sResult = "">		

		<cfif Len(variables.sHttpURL) IS 0>
			<cfset sResult = arguments.sScheme & cgi.http_host & cgi.path_info>
		<cfelse>
			<cfset sResult = variables.sHttpURL>
		</cfif>
		<cfreturn sResult>
	</cffunction>

	<!--- return a string that consists of all the parameters that need to be signed --->
	<cffunction name="getSignableParameters" access="public" returntype="string">
		<cfset var aResult = ArrayNew(1)>
		<cfset var sResult = "">
		<cfset var sKey = "">

		<cfset var aKeys = StructKeyArray(getParameters())>
		<cfset ArraySort(aKeys, "textnocase")>

		<cfloop list="#ArrayToList(aKeys)#" index="sKey">
			<!--- skip 'oauth_signature'-parameter --->
			<cfif sKey NEQ "oauth_signature">
				<cfset 	ArrayAppend(aResult, sKey & "=" & StructFind(variables.stParameters, sKey) )>
			</cfif>
		</cfloop>

		<cfset sResult = ArrayToList(aResult, "&")>
		<cfreturn sResult>
	</cffunction>

	<!--- builds an URL usable for a GET request --->
	<cffunction name="toURL" access="public" output="false" returntype="string">
		<cfset var sResult = getNormalizedHttpURL() & "?">
		<cfset sResult = sResult & toPostData()>
		<cfreturn sResult>
	</cffunction>

  	<!--- builds the data one would send in a POST request, parameters are sorted alphabetically & url encoded --->
	<cffunction name="toPostData" access="public" returntype="string">
		<cfset var aTotal = ArrayNew(1)>
		<cfset var sResult = "">
		<cfset var sKey = "">
		<cfset var aKeys = StructKeyArray(getParameters())>
		<cfset ArraySort(aKeys, "textnocase")>

		<cfloop list="#ArrayToList(aKeys)#" index="sKey">
			<cfset ArrayAppend(aTotal, 
				URLEncodedFormat(sKey) & "=" & URLEncodedFormat(StructFind(variables.stParameters, sKey)) )>
		</cfloop>

		<cfset sResult = ArrayToList(aTotal, "&")>

		<cfreturn sResult>
	</cffunction>
  
  	<!--- builds the Authorization: header --->
	<cffunction name="toHeader" access="public" returntype="string" output="false">
		<cfargument name="sHeaderRealm" default="" required="false" type="string">

		<cfset var sRealm = arguments.sHeaderRealm>
		<cfset var sResult = "">
		<cfset var aTotal = ArrayNew(1)>
		<cfset var sKey = "">

		<!--- optional realm parameter --->
		<cfset sResult = """Authorization: OAuth realm=""" & sRealm & """,">

		<cfloop collection="#variables.stParameters#" item="sKey">
			<cfif Left(sKey, 5) EQ "oauth">
				<cfset ArrayAppend(aTotal, 
					URLEncodedFormat(sKey) & "=""" & URLEncodedFormat(StructFind(variables.stParameters,sKey)) & """")>
			</cfif>
		</cfloop>
		<cfset sResult = sResult & ArrayToList(aTotal, ",")>
		<cfreturn sResult>
	</cffunction>

	<cffunction name="getString" access="public" returntype="string">
		<cfreturn toURL()>
	</cffunction>

	<cffunction name="signRequest" access="public" returntype="void" output="false">
		<cfargument name="oSignatureMethod"	required="true" type="OAuthSignatureMethod">
		<cfargument name="oConsumer" 		required="true" type="OAuthConsumer">
		<cfargument name="oToken" 			required="true" type="OAuthToken">

		<cfset var sSignature = "">

		<cfset setParameter("oauth_signature_method", arguments.oSignatureMethod.getName())>
		<cfset sSignature = buildSignature(arguments.oSignatureMethod, arguments.oConsumer, arguments.oToken)>
		<cfset setParameter("oauth_signature", sSignature)>
	</cffunction>

	<!--- build url encoded signature --->
	<cffunction name="signatureBaseString" access="public" returntype="string">
		<cfset var aResult = ArrayNew(1)>
		<cfset ArrayAppend(aResult, URLEncodedFormat(getNormalizedHttpMethod()) )>
		<cfset ArrayAppend(aResult, URLEncodedFormat(getNormalizedHttpURL()) )>
		<cfset ArrayAppend(aResult, URLEncodedFormat(getSignableParameters()) )>

		<cfreturn ArrayToList(aResult, "&")>
	</cffunction>

	<cffunction name="buildSignature" access="public" returntype="string" output="false">
		<cfargument name="oSignatureMethod"	required="true" type="OAuthSignatureMethod">
		<cfargument name="oConsumer" 		required="true" type="OAuthConsumer">
		<cfargument name="oToken" 			required="true" type="OAuthToken">

		<cfset var sSignature = arguments.oSignatureMethod.buildSignature(this, arguments.oConsumer, arguments.oToken)>

		<cfreturn sSignature>
	</cffunction>

	<!--- util function: current timestamp --->
	<cffunction name="generateTimestamp" access="public" returntype="numeric">
		<cfset var tc = CreateObject("java", "java.util.Date").getTime()>
		<cfreturn Int(tc / 1000)>
	</cffunction>

	<!--- util function: current nonce --->
	<cffunction name="generateNonce" access="public" returntype="string" output="false" hint="generate nonce value">
		<cfset var iMin = 0>
		<cfset var iMax = CreateObject("java","java.lang.Integer").MAX_VALUE>
		<cfset var sToEncode = generateTimestamp() & RandRange(iMin, iMax)>

		<cfreturn Hash(sToEncode, "SHA")/>
	</cffunction>

	<!--- util function for turning the Authorization: header into parameters, has to do some unescaping --->
	<cffunction name="splitHeader" access="private" output="false" returntype="struct">
  		<cfargument name="sHeader" type="string" required="true" hint="authorization request header">

		<cfset var aHeaderParts = ArrayNew(1)>
		<cfset var aParameterParts = ArrayNew(1)>
		<cfset var stResult = StructNew()>
    	<cfset var sParam = "">

		<cfset aHeaderParts = ListToArray(arguments.sHeader, ",")>

		<cfloop collection="#aHeaderParts#" item="sParam">
			<cfset sParam = LTrim(sParam)>

		    <cfif Left(sParam, 5) EQ "oauth">
			    <cfset aParameterParts = ListToArray(sParam, "=")>
			    <cfset stResult[aParameterParts[1]] = URLDecode(aParameterParts[2])>
		    </cfif>
		</cfloop>

		<cfreturn stResult>
	</cffunction>

</cfcomponent>
