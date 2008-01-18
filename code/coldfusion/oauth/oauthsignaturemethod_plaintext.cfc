<!---
$HeadURL$
$Id$
Description:
============
	OAuth signaturemethod "plaintext"

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

<cfcomponent extends="OAuthSignatureMethod" displayname="OAuthSignatureMethod_PLAINTEXT" hint="signature method using plaintext encoding">

	<!--- returns the signature method name --->
	<cffunction name="getName" access="public" returntype="string" output="false">
		<cfreturn "PLAINTEXT">
	</cffunction>

	<!--- builds a plaintext signature	--->
	<cffunction name="buildSignature" access="public" returntype="string">
		<cfargument name="oRequest" 	required="true"	type="OAuthRequest">
		<cfargument name="oConsumer" 	required="true" type="OAuthConsumer">
		<cfargument name="oToken"		required="true"	type="OAuthToken">

		<cfset var aSignature = ArrayNew(1)>
		<cfset var sResult = "">

		<cfset ArrayAppend(aSignature, URLEncodedFormat(arguments.oConsumer.getSecret()))>

		<cfif NOT arguments.oToken.isEmpty()>
			<cfset ArrayAppend(aSignature, URLEncodedFormat(arguments.oToken.getSecret()))>
		<cfelse>
			<cfset ArrayAppend(aSignature, "")>
		</cfif>

		<cfset sResult = ArrayToList(aSignature, "&")>

		<cfreturn sResult>
	</cffunction>

</cfcomponent>