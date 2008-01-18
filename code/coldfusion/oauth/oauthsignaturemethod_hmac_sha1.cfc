<!---
$HeadURL$
$Id$
Description:
============
	OAuth signaturemethod "HMAC SHA1"

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

<cfcomponent extends="OAuthSignatureMethod" displayname="OAuthSignatureMethod_HMAC_SHA1" hint="signature method using HMAC-SHA1">

	<!--- returns the signature name --->
	<cffunction name="getName" access="public" returntype="string" output="false">
		<cfreturn "HMAC-SHA1">
	</cffunction>

	<!--- builds a SHA-1 signature --->
	<cffunction name="buildSignature" access="public" returntype="string">
		<cfargument name="oRequest"		required="true" type="OAuthRequest">
		<cfargument name="oConsumer"	required="true" type="OAuthConsumer">
		<cfargument name="oToken"		required="true" type="OAuthToken">	

		<cfset var aSignature = ArrayNew(1)>
		<cfset var sKey = "">
		<cfset var sResult = "">
		<cfset var sHashed = "">
		<cfset var digest = "">

		<cfset ArrayAppend(aSignature, arguments.oRequest.getNormalizedHttpMethod())>
		<cfset ArrayAppend(aSignature, arguments.oRequest.getNormalizedHttpURL())>
		<cfset ArrayAppend(aSignature, arguments.oRequest.getSignableParameters())>

		<cfset sKey = arguments.oConsumer.getSecret() & "&">
		<cfset sKey = sKey & arguments.oToken.getSecret()>
		<cfset sResult = ArrayToList(aSignature, "&")>

		<cfset digest = hmac(
			data = sResult,
			key	 = sKey,
			hash_function = "sha1",
			output_bits = "160")><!--- 160 bits - standart SHA-1 length --->

		<cfset sHashed = ToBase64(digest)>

		<cfreturn sHashed>
	</cffunction>

	<cffunction name="hmac" access="public" returntype="string">
		<!---
		Original programmer: Tim McCarthy (tim@timmcc.com)
		Date: February, 2003
		Description:
			Implements HMAC, a mechanism for message authentication using hash functions
			as specified in RFC 2104 (http://www.ietf.org/rfc/rfc2104.txt).  HMAC requires
			a hash function H and a secret key K and is computed as follows:
				H(K XOR opad, H(K XOR ipad, data)), where
					ipad = the byte 0x36 repeated 64 times
					opad = the byte 0x5c repeated 64 times
					data = the data to be authenticated
		Required parameters: data, key
		Optional parameters:
			data_format: hex = data is in hexadecimal format (default is ASCII text)
			key_format: hex = key is in hexadecimal format (default is ASCII text)
			hash_function: md5, sha1, sha256, or ripemd160 (default is md5)
			output_bits: truncate output to leftmost bits indicated (default is all)
		Note:
			This version accepts input in both ASCII text and hexadecimal formats.
		--->
		<cfargument name="data" required="true" type="string">
		<cfargument name="key" required="true" type="string">
		<cfargument name="data_format" default="">
		<cfargument name="key_format" default="">
		<cfargument name="hash_function" default="md5">
		<cfargument name="output_bits" default="256">

		<cfset var hex_data = "">
		<cfset var hex_key = "">
		<cfset var key_len = 0>
		<cfset var key_ipad = "">
		<cfset var key_opad = "">
		<cfset var msg_digest = "">
		<cfset var i = 1>

		<!--- convert data to ASCII binary-coded form --->
		<cfif arguments.data_format EQ "hex">
			<cfset hex_data = arguments.data>
		<cfelse>
			<cfloop index="i" from="1" to="#Len(arguments.data)#">
				<cfset hex_data = hex_data & Right("0"&FormatBaseN(Asc(Mid(arguments.data,i,1)),16),2)>
			</cfloop>
		</cfif>

		<!--- convert key to ASCII binary-coded form --->
		<cfif arguments.key_format EQ "hex">
			<cfset hex_key = arguments.key>
		<cfelse>
			<cfloop index="i" from="1" to="#Len(arguments.key)#">
				<cfset hex_key = hex_key & Right("0"&FormatBaseN(Asc(Mid(arguments.key,i,1)),16),2)>
			</cfloop>
		</cfif>

		<cfset key_len = Len(hex_key)/2>

		<!--- if key longer than 64 bytes, use hash of key as key --->
		<cfif key_len GT 64>
			<cfswitch expression="#arguments.hash_function#">
				<cfcase value="md5">
					<cfset hex_key = md5(msg=hex_key, format="hex")>
				</cfcase>
				<cfcase value="sha1">
					<cfset hex_key = sha_1(msg=hex_key, format="hex")>
				</cfcase>
				<cfcase value="sha256">
					<cfset hex_key = sha_256(msg=hex_key, format="hex")>
				</cfcase>
				<cfcase value="ripemd160">
					<cfset hex_key = ripemd_160(msg=hex_key, format="hex")>
				</cfcase>
			</cfswitch>
			<cfset key_len = Len(hex_key)/2>
		</cfif>

		<cfloop index="i" from="1" to="#key_len#">
			<cfset key_ipad = key_ipad & Right("0"&FormatBaseN(BitXor(InputBaseN(Mid(hex_key,2*i-1,2),16),InputBaseN("36",16)),16),2)>
			<cfset key_opad = key_opad & Right("0"&FormatBaseN(BitXor(InputBaseN(Mid(hex_key,2*i-1,2),16),InputBaseN("5c",16)),16),2)>
		</cfloop>
		<cfset key_ipad = key_ipad & RepeatString("36",64-key_len)>
		<cfset key_opad = key_opad & RepeatString("5c",64-key_len)>

		<cfswitch expression="#arguments.hash_function#">
			<cfcase value="md5">
				<cfset msg_digest = md5(msg="#key_ipad##hex_data#", format="hex")>
				<cfset msg_digest = md5(msg="#key_opad##msg_digest#", format="hex")>
			</cfcase>
			<cfcase value="sha1">
				<cfset msg_digest = sha_1(msg="#key_ipad##hex_data#", format="hex")>
				<cfset msg_digest = sha_1(msg="#key_opad##msg_digest#", format="hex")>
			</cfcase>
			<cfcase value="sha256">
				<cfset msg_digest = sha_256(msg="#key_ipad##hex_data#", format="hex")>
				<cfset msg_digest = sha_256(msg="#key_opad##msg_digest#", format="hex")>
			</cfcase>
			<cfcase value="ripemd160">
				<cfset msg_digest = ripemd_160(msg="#key_ipad##hex_data#", format="hex")>
				<cfset msg_digest = ripemd_160(msg="#key_opad##msg_digest#", format="hex")>
			</cfcase>
		</cfswitch>

		<cfreturn Left(msg_digest, arguments.output_bits/4)>
	</cffunction>

	<cffunction name="md5" access="public" returntype="string">
		<!---
		Original programmer: Tim McCarthy (tim@timmcc.com)
		Date: February, 2003
		Description:
			Produces a 128-bit condensed representation of a message (arguments.msg) called
			a message digest (caller.msg_digest) using the RSA MD5 message-digest algorithm
			as specified in RFC 1321 (http://www.ietf.org/rfc/rfc1321.txt)
		Required parameter: msg
		Optional parameter: format="hex" (hexadecimal, default is ASCII text)
		Note:
			This version accepts input in both ASCII text and hexadecimal formats.
		--->
		<cfargument name="msg" required="true" type="string">
		<cfargument name="format" default="">

		<cfset var hex_msg = "">
		<cfset var hex_msg_len = 0>
		<cfset var temp = "">
		<cfset var padded_hex_msg = "">
		<cfset var aVar = ArrayNew(1)>
		<cfset var a = "">
		<cfset var b = "">
		<cfset var c = "">
		<cfset var d = "">
		<cfset var h = ArrayNew(1)>
		<cfset var m = ArrayNew(1)>
		<cfset var t = ArrayNew(1)>
		<cfset var k = ArrayNew(1)>
		<cfset var s = ArrayNew(1)>
		<cfset var msg_block = "">
		<cfset var sub_block = "">
		<cfset var i = 1>
		<cfset var j = 1>
		<cfset var n = 1>
		<cfset var f = 0>

		<!--- convert the msg to ASCII binary-coded form --->
		<cfif arguments.format EQ "hex">
			<cfset hex_msg = arguments.msg>
		<cfelse>
			<cfloop index="i" from="1" to="#Len(arguments.msg)#">
				<cfset hex_msg = hex_msg & Right("0"&FormatBaseN(Asc(Mid(arguments.msg,i,1)),16),2)>
			</cfloop>
		</cfif>

		<!--- compute the msg length in bits --->
		<cfset hex_msg_len = Right(RepeatString("0",15)&FormatBaseN(4*Len(hex_msg),16),16)>
		<cfloop index="i" from="1" to="8">
			<cfset temp = temp & Mid(hex_msg_len,-2*(i-8)+1,2)>
		</cfloop>
		<cfset hex_msg_len = temp>

		<!--- pad the msg to make it a multiple of 512 bits long --->
		<cfset padded_hex_msg = hex_msg & "80" & RepeatString("0",128-((Len(hex_msg)+2+16) Mod 128)) & hex_msg_len>

		<!--- initialize MD buffer --->
		<cfset h[1] = InputBaseN("0x67452301",16)>
		<cfset h[2] = InputBaseN("0xefcdab89",16)>
		<cfset h[3] = InputBaseN("0x98badcfe",16)>
		<cfset h[4] = InputBaseN("0x10325476",16)>

		<cfset aVar[1] = "a">
		<cfset aVar[2] = "b">
		<cfset aVar[3] = "c">
		<cfset aVar[4] = "d">

		<cfloop index="i" from="1" to="64">
			<cfset t[i] = Int(2^32*abs(sin(i)))>
			<cfif i LE 16>
				<cfif i EQ 1>
					<cfset k[i] = 0>
				<cfelse>
					<cfset k[i] = k[i-1] + 1>
				</cfif>
				<cfset s[i] = 5*((i-1) MOD 4) + 7>
			<cfelseIF i LE 32>
				<cfif i EQ 17>
					<cfset k[i] = 1>
				<cfelse>
					<cfset k[i] = (k[i-1]+5) MOD 16>
				</cfif>
				<cfset s[i] = 0.5*((i-1) MOD 4)*((i-1) MOD 4) + 3.5*((i-1) MOD 4) + 5>
			<cfelseIF i LE 48>
				<cfif i EQ 33>
					<cfset k[i] = 5>
				<cfelse>
					<cfset k[i] = (k[i-1]+3) MOD 16>
				</cfif>
				<cfset s[i] = 6*((i-1) MOD 4) + ((i-1) MOD 2) + 4>
			<cfelse>
				<cfif i EQ 49>
					<cfset k[i] = 0>
				<cfelse>
					<cfset k[i] = (k[i-1]+7) MOD 16>
				</cfif>
				<cfset s[i] = 0.5*((i-1) MOD 4)*((i-1) MOD 4) + 3.5*((i-1) MOD 4) + 6>
			</cfif>
		</cfloop>

		<!--- process the msg 512 bits at a time --->
		<cfloop index="n" from="1" to="#Evaluate(Len(padded_hex_msg)/128)#">

			<cfset a = h[1]>
			<cfset b = h[2]>
			<cfset c = h[3]>
			<cfset d = h[4]>

			<cfset msg_block = Mid(padded_hex_msg,128*(n-1)+1,128)>
			<cfloop index="i" from="1" to="16">
				<cfset sub_block = "">
				<cfloop index="j" from="1" to="4">
					<cfset sub_block = sub_block & Mid(msg_block,8*i-2*j+1,2)>
				</cfloop>
				<cfset m[i] = InputBaseN(sub_block,16)>
			</cfloop>

			<cfloop index="i" from="1" to="64">

				<cfif i LE 16>
					<cfset f = BitOr(BitAnd(Evaluate(aVar[2]),Evaluate(aVar[3])),BitAnd(BitNot(Evaluate(aVar[2])),Evaluate(aVar[4])))>
				<cfelseIF i LE 32>
					<cfset f = BitOr(BitAnd(Evaluate(aVar[2]),Evaluate(aVar[4])),BitAnd(Evaluate(aVar[3]),BitNot(Evaluate(aVar[4]))))>
				<cfelseIF i LE 48>
					<cfset f = BitXor(BitXor(Evaluate(aVar[2]),Evaluate(aVar[3])),Evaluate(aVar[4]))>
				<cfelse>
					<cfset f = BitXor(Evaluate(aVar[3]),BitOr(Evaluate(aVar[2]),BitNot(Evaluate(aVar[4]))))>
				</cfif>

				<cfset temp = Evaluate(aVar[1]) + f + m[k[i]+1] + t[i]>
				<cfloop condition="(temp LT -2^31) OR (temp GE 2^31)">
					<cfset temp = temp - Sgn(temp)*2^32>
				</cfloop>
				<cfset temp = Evaluate(aVar[2]) + BitOr(BitSHLN(temp,s[i]),BitSHRN(temp,32-s[i]))>
				<cfloop condition="(temp LT -2^31) OR (temp GE 2^31)">
					<cfset temp = temp - Sgn(temp)*2^32>
				</cfloop>
				<cfset temp = SetVariable(aVar[1],temp)>

				<cfset temp = aVar[4]>
				<cfset aVar[4] = aVar[3]>
				<cfset aVar[3] = aVar[2]>
				<cfset aVar[2] = aVar[1]>
				<cfset aVar[1] = temp>

			</cfloop>

			<cfset h[1] = h[1] + a>
			<cfset h[2] = h[2] + b>
			<cfset h[3] = h[3] + c>
			<cfset h[4] = h[4] + d>

			<cfloop index="i" from="1" to="4">
				<cfloop condition="(h[i] LT -2^31) OR (h[i] GE 2^31)">
					<cfset h[i] = h[i] - Sgn(h[i])*2^32>
				</cfloop>
			</cfloop>

		</cfloop>

		<cfloop index="i" from="1" to="4">
			<cfset h[i] = Right(RepeatString("0",7)&UCase(FormatBaseN(h[i],16)),8)>
		</cfloop>

		<cfloop index="i" from="1" to="4">
			<cfset temp = "">
			<cfloop index="j" from="1" to="4">
				<cfset temp = temp & Mid(h[i],-2*(j-4)+1,2)>
			</cfloop>
			<cfset h[i] = temp>
		</cfloop>

		<cfreturn h[1] & h[2] & h[3] & h[4]>
	</cffunction>

	<cffunction name="ripemd_160" access="public" returntype="string">
		<!---
		Original programmer: Tim McCarthy (tim@timmcc.com)
		Date: February, 2003
		Description:
			Produces a 160-bit condensed representation of a message (arguments.msg) called
			a message digest (caller.msg_digest) using the RIPEMD-160 hash function as
			specified in http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
		Required parameter: msg
		Optional parameter: format="hex" (hexadecimal, default is ASCII text)
		Note:
			This version accepts input in both ASCII text and hexadecimal formats.
		--->
		<cfargument name="msg" required="true" type="string">
		<cfargument name="format" default="">

		<cfset var hex_msg = "">
		<cfset var hex_msg_len = 0>
		<cfset var temp = "">
		<cfset var padded_hex_msg = "">
		<cfset var rho = ArrayNew(1)>
		<cfset var pi = ArrayNew(1)>
		<cfset var shift = ArrayNew(2)>
		<cfset var k1 = ArrayNew(1)>
		<cfset var k2 = ArrayNew(1)>
		<cfset var r1 = ArrayNew(1)>
		<cfset var r2 = ArrayNew(1)>
		<cfset var s1 = ArrayNew(1)>
		<cfset var s2 = ArrayNew(1)>
		<cfset var h = ArrayNew(1)>
		<cfset var var1 = ArrayNew(1)>
		<cfset var var2 = ArrayNew(1)>
		<cfset var x = ArrayNew(1)>
		<cfset var a1 = "">
		<cfset var b1 = "">
		<cfset var c1 = "">
		<cfset var d1 = "">
		<cfset var e1 = "">
		<cfset var a2 = "">
		<cfset var b2 = "">
		<cfset var c2 = "">
		<cfset var d2 = "">
		<cfset var e2 = "">
		<cfset var t = "">
		<cfset var msg_block = "">
		<cfset var sub_block = "">
		<cfset var i = 1>
		<cfset var j = 1>
		<cfset var n = 1>
		<cfset var f1 = 0>
		<cfset var f2 = 0>

		<!--- convert the msg to ASCII binary-coded form --->
		<cfif arguments.format EQ "hex">
			<cfset hex_msg = arguments.msg>
		<cfelse>
			<cfloop index="i" from="1" to="#Len(arguments.msg)#">
				<cfset hex_msg = hex_msg & Right("0"&FormatBaseN(Asc(Mid(arguments.msg,i,1)),16),2)>
			</cfloop>
		</cfif>

		<!--- compute the msg length in bits --->
		<cfset hex_msg_len = Right(RepeatString("0",15)&FormatBaseN(4*Len(hex_msg),16),16)>
		<cfloop index="i" from="1" to="8">
			<cfset temp = temp & Mid(hex_msg_len,-2*(i-8)+1,2)>
		</cfloop>
		<cfset hex_msg_len = temp>

		<!--- pad the msg to make it a multiple of 512 bits long --->
		<cfset padded_hex_msg = hex_msg & "80" & RepeatString("0",128-((Len(hex_msg)+2+16) Mod 128)) & hex_msg_len>

		<!--- define permutations --->
		<cfset rho[1] = 7>
		<cfset rho[2] = 4>
		<cfset rho[3] = 13>
		<cfset rho[4] = 1>
		<cfset rho[5] = 10>
		<cfset rho[6] = 6>
		<cfset rho[7] = 15>
		<cfset rho[8] = 3>
		<cfset rho[9] = 12>
		<cfset rho[10] = 0>
		<cfset rho[11] = 9>
		<cfset rho[12] = 5>
		<cfset rho[13] = 2>
		<cfset rho[14] = 14>
		<cfset rho[15] = 11>
		<cfset rho[16] = 8>

		<cfloop index="i" from="1" to="16">
			<cfset pi[i] = (9*(i-1)+5) Mod 16>
		</cfloop>

		<!--- define shifts --->
		<cfset shift[1][1] = 11>
		<cfset shift[1][2] = 14>
		<cfset shift[1][3] = 15>
		<cfset shift[1][4] = 12>
		<cfset shift[1][5] = 5>
		<cfset shift[1][6] = 8>
		<cfset shift[1][7] = 7>
		<cfset shift[1][8] = 9>
		<cfset shift[1][9] = 11>
		<cfset shift[1][10] = 13>
		<cfset shift[1][11] = 14>
		<cfset shift[1][12] = 15>
		<cfset shift[1][13] = 6>
		<cfset shift[1][14] = 7>
		<cfset shift[1][15] = 9>
		<cfset shift[1][16] = 8>
		<cfset shift[2][1] = 12>
		<cfset shift[2][2] = 13>
		<cfset shift[2][3] = 11>
		<cfset shift[2][4] = 15>
		<cfset shift[2][5] = 6>
		<cfset shift[2][6] = 9>
		<cfset shift[2][7] = 9>
		<cfset shift[2][8] = 7>
		<cfset shift[2][9] = 12>
		<cfset shift[2][10] = 15>
		<cfset shift[2][11] = 11>
		<cfset shift[2][12] = 13>
		<cfset shift[2][13] = 7>
		<cfset shift[2][14] = 8>
		<cfset shift[2][15] = 7>
		<cfset shift[2][16] = 7>
		<cfset shift[3][1] = 13>
		<cfset shift[3][2] = 15>
		<cfset shift[3][3] = 14>
		<cfset shift[3][4] = 11>
		<cfset shift[3][5] = 7>
		<cfset shift[3][6] = 7>
		<cfset shift[3][7] = 6>
		<cfset shift[3][8] = 8>
		<cfset shift[3][9] = 13>
		<cfset shift[3][10] = 14>
		<cfset shift[3][11] = 13>
		<cfset shift[3][12] = 12>
		<cfset shift[3][13] = 5>
		<cfset shift[3][14] = 5>
		<cfset shift[3][15] = 6>
		<cfset shift[3][16] = 9>
		<cfset shift[4][1] = 14>
		<cfset shift[4][2] = 11>
		<cfset shift[4][3] = 12>
		<cfset shift[4][4] = 14>
		<cfset shift[4][5] = 8>
		<cfset shift[4][6] = 6>
		<cfset shift[4][7] = 5>
		<cfset shift[4][8] = 5>
		<cfset shift[4][9] = 15>
		<cfset shift[4][10] = 12>
		<cfset shift[4][11] = 15>
		<cfset shift[4][12] = 14>
		<cfset shift[4][13] = 9>
		<cfset shift[4][14] = 9>
		<cfset shift[4][15] = 8>
		<cfset shift[4][16] = 6>
		<cfset shift[5][1] = 15>
		<cfset shift[5][2] = 12>
		<cfset shift[5][3] = 13>
		<cfset shift[5][4] = 13>
		<cfset shift[5][5] = 9>
		<cfset shift[5][6] = 5>
		<cfset shift[5][7] = 8>
		<cfset shift[5][8] = 6>
		<cfset shift[5][9] = 14>
		<cfset shift[5][10] = 11>
		<cfset shift[5][11] = 12>
		<cfset shift[5][12] = 11>
		<cfset shift[5][13] = 8>
		<cfset shift[5][14] = 6>
		<cfset shift[5][15] = 5>
		<cfset shift[5][16] = 5>

		<cfloop index="i" from="1" to="16">

			<!--- define constants --->
			<cfset k1[i] = 0>
			<cfset k1[i+16] = Int(2^30*Sqr(2))>
			<cfset k1[i+32] = Int(2^30*Sqr(3))>
			<cfset k1[i+48] = Int(2^30*Sqr(5))>
			<cfset k1[i+64] = Int(2^30*Sqr(7))>

			<cfset k2[i] = Int(2^30*2^(1/3))>
			<cfset k2[i+16] = Int(2^30*3^(1/3))>
			<cfset k2[i+32] = Int(2^30*5^(1/3))>
			<cfset k2[i+48] = Int(2^30*7^(1/3))>
			<cfset k2[i+64] = 0>

			<!--- define word order --->
			<cfset r1[i] = i-1>
			<cfset r1[i+16] = rho[i]>
			<cfset r1[i+32] = rho[rho[i]+1]>
			<cfset r1[i+48] = rho[rho[rho[i]+1]+1]>
			<cfset r1[i+64] = rho[rho[rho[rho[i]+1]+1]+1]>

			<cfset r2[i] = pi[i]>
			<cfset r2[i+16] = rho[pi[i]+1]>
			<cfset r2[i+32] = rho[rho[pi[i]+1]+1]>
			<cfset r2[i+48] = rho[rho[rho[pi[i]+1]+1]+1]>
			<cfset r2[i+64] = rho[rho[rho[rho[pi[i]+1]+1]+1]+1]>

			<!--- define rotations --->
			<cfset s1[i] = shift[1][r1[i]+1]>
			<cfset s1[i+16] = shift[2][r1[i+16]+1]>
			<cfset s1[i+32] = shift[3][r1[i+32]+1]>
			<cfset s1[i+48] = shift[4][r1[i+48]+1]>
			<cfset s1[i+64] = shift[5][r1[i+64]+1]>
			
			<cfset s2[i] = shift[1][r2[i]+1]>
			<cfset s2[i+16] = shift[2][r2[i+16]+1]>
			<cfset s2[i+32] = shift[3][r2[i+32]+1]>
			<cfset s2[i+48] = shift[4][r2[i+48]+1]>
			<cfset s2[i+64] = shift[5][r2[i+64]+1]>

		</cfloop>

		<!--- define buffers --->
		<cfset h[1] = InputBaseN("0x67452301",16)>
		<cfset h[2] = InputBaseN("0xefcdab89",16)>
		<cfset h[3] = InputBaseN("0x98badcfe",16)>
		<cfset h[4] = InputBaseN("0x10325476",16)>
		<cfset h[5] = InputBaseN("0xc3d2e1f0",16)>

		<cfset var1[1] = "a1">
		<cfset var1[2] = "b1">
		<cfset var1[3] = "c1">
		<cfset var1[4] = "d1">
		<cfset var1[5] = "e1">

		<cfset var2[1] = "a2">
		<cfset var2[2] = "b2">
		<cfset var2[3] = "c2">
		<cfset var2[4] = "d2">
		<cfset var2[5] = "e2">

		<!--- process msg in 16-word blocks --->
		<cfloop index="n" from="1" to="#Evaluate(Len(padded_hex_msg)/128)#">

			<cfset a1 = h[1]>
			<cfset b1 = h[2]>
			<cfset c1 = h[3]>
			<cfset d1 = h[4]>
			<cfset e1 = h[5]>

			<cfset a2 = h[1]>
			<cfset b2 = h[2]>
			<cfset c2 = h[3]>
			<cfset d2 = h[4]>
			<cfset e2 = h[5]>

			<cfset msg_block = Mid(padded_hex_msg,128*(n-1)+1,128)>
			<cfloop index="i" from="1" to="16">
				<cfset sub_block = "">
				<cfloop index="j" from="1" to="4">
					<cfset sub_block = sub_block & Mid(msg_block,8*i-2*j+1,2)>
				</cfloop>
				<cfset x[i] = InputBaseN(sub_block,16)>
			</cfloop>

			<cfloop index="j" from="1" to="80">

				<!--- nonlinear functions --->
				<cfif j LE 16>
					<cfset f1 = BitXor(BitXor(Evaluate(var1[2]),Evaluate(var1[3])),Evaluate(var1[4]))>
					<cfset f2 = BitXor(Evaluate(var2[2]),BitOr(Evaluate(var2[3]),BitNot(Evaluate(var2[4]))))>
				<cfelseIF j LE 32>
					<cfset f1 = BitOr(BitAnd(Evaluate(var1[2]),Evaluate(var1[3])),BitAnd(BitNot(Evaluate(var1[2])),Evaluate(var1[4])))>
					<cfset f2 = BitOr(BitAnd(Evaluate(var2[2]),Evaluate(var2[4])),BitAnd(Evaluate(var2[3]),BitNot(Evaluate(var2[4]))))>
				<cfelseIF j LE 48>
					<cfset f1 = BitXor(BitOr(Evaluate(var1[2]),BitNot(Evaluate(var1[3]))),Evaluate(var1[4]))>
					<cfset f2 = BitXor(BitOr(Evaluate(var2[2]),BitNot(Evaluate(var2[3]))),Evaluate(var2[4]))>
				<cfelseIF j LE 64>
					<cfset f1 = BitOr(BitAnd(Evaluate(var1[2]),Evaluate(var1[4])),BitAnd(Evaluate(var1[3]),BitNot(Evaluate(var1[4]))))>
					<cfset f2 = BitOr(BitAnd(Evaluate(var2[2]),Evaluate(var2[3])),BitAnd(BitNot(Evaluate(var2[2])),Evaluate(var2[4])))>
				<cfelse>
					<cfset f1 = BitXor(Evaluate(var1[2]),BitOr(Evaluate(var1[3]),BitNot(Evaluate(var1[4]))))>
					<cfset f2 = BitXor(BitXor(Evaluate(var2[2]),Evaluate(var2[3])),Evaluate(var2[4]))>
				</cfif>

				<cfset temp = Evaluate(var1[1]) + f1 + x[r1[j]+1] + k1[j]>
				<cfloop condition="(temp LT -2^31) OR (temp GE 2^31)">
					<cfset temp = temp - Sgn(temp)*2^32>
				</cfloop>
				<cfset temp = BitOr(BitSHLN(temp,s1[j]),BitSHRN(temp,32-s1[j])) + Evaluate(var1[5])>
				<cfloop condition="(temp LT -2^31) OR (temp GE 2^31)">
					<cfset temp = temp - Sgn(temp)*2^32>
				</cfloop>
				<cfset temp = SetVariable(var1[1],temp)>
				<cfset temp = SetVariable(var1[3],BitOr(BitSHLN(Evaluate(var1[3]),10),BitSHRN(Evaluate(var1[3]),32-10)))>

				<cfset temp = var1[5]>
				<cfset var1[5] = var1[4]>
				<cfset var1[4] = var1[3]>
				<cfset var1[3] = var1[2]>
				<cfset var1[2] = var1[1]>
				<cfset var1[1] = temp>

				<cfset temp = Evaluate(var2[1]) + f2 + x[r2[j]+1] + k2[j]>
				<cfloop condition="(temp LT -2^31) OR (temp GE 2^31)">
					<cfset temp = temp - Sgn(temp)*2^32>
				</cfloop>
				<cfset temp = BitOr(BitSHLN(temp,s2[j]),BitSHRN(temp,32-s2[j])) + Evaluate(var2[5])>
				<cfloop condition="(temp LT -2^31) OR (temp GE 2^31)">
					<cfset temp = temp - Sgn(temp)*2^32>
				</cfloop>
				<cfset temp = SetVariable(var2[1],temp)>
				<cfset temp = SetVariable(var2[3],BitOr(BitSHLN(Evaluate(var2[3]),10),BitSHRN(Evaluate(var2[3]),32-10)))>

				<cfset temp = var2[5]>
				<cfset var2[5] = var2[4]>
				<cfset var2[4] = var2[3]>
				<cfset var2[3] = var2[2]>
				<cfset var2[2] = var2[1]>
				<cfset var2[1] = temp>

			</cfloop>

			<cfset t = h[2] + c1 + d2>
			<cfset h[2] = h[3] + d1 + e2>
			<cfset h[3] = h[4] + e1 + a2>
			<cfset h[4] = h[5] + a1 + b2>
			<cfset h[5] = h[1] + b1 + c2>
			<cfset h[1] = t>

			<cfloop index="i" from="1" to="5">
				<cfloop condition="(h[i] LT -2^31) OR (h[i] GE 2^31)">
					<cfset h[i] = h[i] - Sgn(h[i])*2^32>
				</cfloop>
			</cfloop>

		</cfloop>

		<cfloop index="i" from="1" to="5">
			<cfset h[i] = Right(RepeatString("0",7)&UCase(FormatBaseN(h[i],16)),8)>
		</cfloop>

		<cfloop index="i" from="1" to="5">
			<cfset temp = "">
			<cfloop index="j" from="1" to="4">
				<cfset temp = temp & Mid(h[i],-2*(j-4)+1,2)>
			</cfloop>
			<cfset h[i] = temp>
		</cfloop>

		<cfreturn h[1] & h[2] & h[3] & h[4] & h[5]>
	</cffunction>

	<cffunction name="sha_1" access="public" returntype="string">
		<!---
		Original programmer: Tim McCarthy (tim@timmcc.com)
		Date: February, 2003
		Description:
			Produces a 160-bit condensed representation of a message (arguments.msg) called
			a message digest (caller.msg_digest) using the Secure Hash Algorithm (SHA-1)
			as specified in FIPS PUB 180-1 (http://www.itl.nist.gov/fipspubs/fip180-1.htm)
		Required parameter: msg
		Optional parameter: format="hex" (hexadecimal, default is ASCII text)
		Note:
			This version accepts input in both ASCII text and hexadecimal formats.
		--->
		<cfargument name="msg" required="true" type="string">
		<cfargument name="format" default="">

		<cfset var hex_msg = "">
		<cfset var hex_msg_len = 0>
		<cfset var temp = "">
		<cfset var padded_hex_msg = "">
		<cfset var h = ArrayNew(1)>
		<cfset var w = ArrayNew(1)>
		<cfset var msg_block = "">
		<cfset var a = "">
		<cfset var b = "">
		<cfset var c = "">
		<cfset var d = "">
		<cfset var e = "">
		<cfset var i = 1>
		<cfset var n = 1>
		<cfset var t = 0>
		<cfset var f = 0>
		<cfset var num = 0>
		<cfset var k = "">

		<!--- convert the msg to ASCII binary-coded form --->
		<cfif arguments.format EQ "hex">
			<cfset hex_msg = arguments.msg>
		<cfelse>
			<cfloop index="i" from="1" to="#Len(arguments.msg)#">
				<cfset hex_msg = hex_msg & Right("0"&FormatBaseN(Asc(Mid(arguments.msg,i,1)),16),2)>
			</cfloop>
		</cfif>

		<!--- compute the msg length in bits --->
		<cfset hex_msg_len = FormatBaseN(4*Len(hex_msg),16)>

		<!--- pad the msg to make it a multiple of 512 bits long --->
		<cfset padded_hex_msg = hex_msg & "80" & RepeatString("0",128-((Len(hex_msg)+2+16) Mod 128)) & RepeatString("0",16-Len(hex_msg_len)) & hex_msg_len>

		<!--- initialize the buffers --->
		<cfset h[1] = InputBaseN("0x67452301",16)>
		<cfset h[2] = InputBaseN("0xefcdab89",16)>
		<cfset h[3] = InputBaseN("0x98badcfe",16)>
		<cfset h[4] = InputBaseN("0x10325476",16)>
		<cfset h[5] = InputBaseN("0xc3d2e1f0",16)>

		<!--- process the msg 512 bits at a time --->
		<cfloop index="n" from="1" to="#Evaluate(Len(padded_hex_msg)/128)#">

			<cfset msg_block = Mid(padded_hex_msg,128*(n-1)+1,128)>

			<cfset a = h[1]>
			<cfset b = h[2]>
			<cfset c = h[3]>
			<cfset d = h[4]>
			<cfset e = h[5]>

			<cfloop index="t" from="0" to="79">

				<!--- nonlinear functions and constants --->
				<cfif t LE 19>
					<cfset f = BitOr(BitAnd(b,c),BitAnd(BitNot(b),d))>
					<cfset k = InputBaseN("0x5a827999",16)>
				<cfelseIF t LE 39>
					<cfset f = BitXor(BitXor(b,c),d)>
					<cfset k = InputBaseN("0x6ed9eba1",16)>
				<cfelseIF t LE 59>
					<cfset f = BitOr(BitOr(BitAnd(b,c),BitAnd(b,d)),BitAnd(c,d))>
					<cfset k = InputBaseN("0x8f1bbcdc",16)>
				<cfelse>
					<cfset f = BitXor(BitXor(b,c),d)>
					<cfset k = InputBaseN("0xca62c1d6",16)>
				</cfif>

				<!--- transform the msg block from 16 32-bit words to 80 32-bit words --->
				<cfif t LE 15>
					<cfset w[t+1] = InputBaseN(Mid(msg_block,8*t+1,8),16)>
				<cfelse>
					<cfset num = BitXor(BitXor(BitXor(w[t-3+1],w[t-8+1]),w[t-14+1]),w[t-16+1])>
					<cfset w[t+1] = BitOr(BitSHLN(num,1),BitSHRN(num,32-1))>
				</cfif>

				<cfset temp = BitOr(BitSHLN(a,5),BitSHRN(a,32-5)) + f + e + w[t+1] + k>
				<cfset e = d>
				<cfset d = c>
				<cfset c = BitOr(BitSHLN(b,30),BitSHRN(b,32-30))>
				<cfset b = a>
				<cfset a = temp>

				<cfset num = a>
				<cfloop condition="(num LT -2^31) OR (num GE 2^31)">
					<cfset num = num - Sgn(num)*2^32>
				</cfloop>
				<cfset a = num>

			</cfloop>

			<cfset h[1] = h[1] + a>
			<cfset h[2] = h[2] + b>
			<cfset h[3] = h[3] + c>
			<cfset h[4] = h[4] + d>
			<cfset h[5] = h[5] + e>

			<cfloop index="i" from="1" to="5">
				<cfloop condition="(h[i] LT -2^31) OR (h[i] GE 2^31)">
					<cfset h[i] = h[i] - Sgn(h[i])*2^32>
				</cfloop>
			</cfloop>

		</cfloop>

		<cfloop index="i" from="1" to="5">
			<cfset h[i] = RepeatString("0",8-Len(FormatBaseN(h[i],16))) & UCase(FormatBaseN(h[i],16))>
		</cfloop>

		<cfreturn h[1] & h[2] & h[3] & h[4] & h[5]>
	</cffunction>

	<cffunction name="sha_256" access="public" returntype="string">
		<!---
		Original programmer: Tim McCarthy (tim@timmcc.com)
		Date: February, 2003
		Description:
			Produces a 256-bit condensed representation of a message (arguments.msg) called
			a message digest (caller.msg_digest) using the Secure Hash Algorithm (SHA-256) as
			specified in FIPS PUB 180-2 (http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf)
			On August 26, 2002, NIST announced the approval of FIPS 180-2, Secure Hash Standard,
			which contains the specifications for the Secure Hash Algorithms (SHA-1, SHA-256, SHA-384,
			and SHA-256) with several examples.  This standard became effective on February 1, 2003.
		Required parameter: msg
		Optional parameter: format="hex" (hexadecimal, default is ASCII text)
		Note:
			This version accepts input in both ASCII text and hexadecimal formats.
		--->
		<cfargument name="msg" required="true" type="string">
		<cfargument name="format" default="">

		<cfset var hex_msg = "">
		<cfset var hex_msg_len = 0>
		<cfset var padded_hex_msg = "">
		<cfset var prime = ArrayNew(1)>
		<cfset var k = ArrayNew(1)>
		<cfset var h = ArrayNew(1)>
		<cfset var w = ArrayNew(1)>
		<cfset var a = "">
		<cfset var b = "">
		<cfset var c = "">
		<cfset var d = "">
		<cfset var e = "">
		<cfset var f = "">
		<cfset var g = "">
		<cfset var hh = 0>
		<cfset var msg_block = "">
		<cfset var smsig0 = 0>
		<cfset var smsig1 = 0>
		<cfset var bgsig0 = 0>
		<cfset var bgsig1 = 0>
		<cfset var ch = 0>
		<cfset var maj = 0>
		<cfset var t1 = 0>
		<cfset var t2 = 0>
		<cfset var i = 1>
		<cfset var n = 1>
		<cfset var t = 0>

		<!--- convert the msg to ASCII binary-coded form --->
		<cfif arguments.format EQ "hex">
			<cfset hex_msg = arguments.msg>
		<cfelse>
			<cfloop index="i" from="1" to="#Len(arguments.msg)#">
				<cfset hex_msg = hex_msg & Right("0"&FormatBaseN(Asc(Mid(arguments.msg,i,1)),16),2)>
			</cfloop>
		</cfif>

		<!--- compute the msg length in bits --->
		<cfset hex_msg_len = FormatBaseN(4*Len(hex_msg),16)>

		<!--- pad the msg to make it a multiple of 512 bits long --->
		<cfset padded_hex_msg = hex_msg & "80" & RepeatString("0",128-((Len(hex_msg)+2+16) Mod 128)) & RepeatString("0",16-Len(hex_msg_len)) & hex_msg_len>

		<!--- first sixty-four prime numbers --->
		<cfset prime[1] = 2>
		<cfset prime[2] = 3>
		<cfset prime[3] = 5>
		<cfset prime[4] = 7>
		<cfset prime[5] = 11>
		<cfset prime[6] = 13>
		<cfset prime[7] = 17>
		<cfset prime[8] = 19>
		<cfset prime[9] = 23>
		<cfset prime[10] = 29>
		<cfset prime[11] = 31>
		<cfset prime[12] = 37>
		<cfset prime[13] = 41>
		<cfset prime[14] = 43>
		<cfset prime[15] = 47>
		<cfset prime[16] = 53>
		<cfset prime[17] = 59>
		<cfset prime[18] = 61>
		<cfset prime[19] = 67>
		<cfset prime[20] = 71>
		<cfset prime[21] = 73>
		<cfset prime[22] = 79>
		<cfset prime[23] = 83>
		<cfset prime[24] = 89>
		<cfset prime[25] = 97>
		<cfset prime[26] = 101>
		<cfset prime[27] = 103>
		<cfset prime[28] = 107>
		<cfset prime[29] = 109>
		<cfset prime[30] = 113>
		<cfset prime[31] = 127>
		<cfset prime[32] = 131>
		<cfset prime[33] = 137>
		<cfset prime[34] = 139>
		<cfset prime[35] = 149>
		<cfset prime[36] = 151>
		<cfset prime[37] = 157>
		<cfset prime[38] = 163>
		<cfset prime[39] = 167>
		<cfset prime[40] = 173>
		<cfset prime[41] = 179>
		<cfset prime[42] = 181>
		<cfset prime[43] = 191>
		<cfset prime[44] = 193>
		<cfset prime[45] = 197>
		<cfset prime[46] = 199>
		<cfset prime[47] = 211>
		<cfset prime[48] = 223>
		<cfset prime[49] = 227>
		<cfset prime[50] = 229>
		<cfset prime[51] = 233>
		<cfset prime[52] = 239>
		<cfset prime[53] = 241>
		<cfset prime[54] = 251>
		<cfset prime[55] = 257>
		<cfset prime[56] = 263>
		<cfset prime[57] = 269>
		<cfset prime[58] = 271>
		<cfset prime[59] = 277>
		<cfset prime[60] = 281>
		<cfset prime[61] = 283>
		<cfset prime[62] = 293>
		<cfset prime[63] = 307>
		<cfset prime[64] = 311>

		<!--- constants --->
		<cfloop index="i" from="1" to="64">
			<cfset k[i] = Int(prime[i]^(1/3)*2^32)>
		</cfloop>

		<!--- initial hash values --->
		<cfloop index="i" from="1" to="8">
			<cfset h[i] = Int(Sqr(prime[i])*2^32)>
			<cfloop condition="(h[i] LT -2^31) OR (h[i] GE 2^31)">
				<cfset h[i] = h[i] - Sgn(h[i])*2^32>
			</cfloop>
		</cfloop>

		<!--- process the msg 512 bits at a time --->
		<cfloop index="n" from="1" to="#Evaluate(Len(padded_hex_msg)/128)#">

			<!--- initialize the eight working variables --->
			<cfset a = h[1]>
			<cfset b = h[2]>
			<cfset c = h[3]>
			<cfset d = h[4]>
			<cfset e = h[5]>
			<cfset f = h[6]>
			<cfset g = h[7]>
			<cfset hh = h[8]>

			<!--- nonlinear functions and message schedule --->
			<cfset msg_block = Mid(padded_hex_msg,128*(n-1)+1,128)>
			<cfloop index="t" from="0" to="63">

				<cfif t LE 15>
					<cfset w[t+1] = InputBaseN(Mid(msg_block,8*t+1,8),16)>
				<cfelse>
					<cfset smsig0 = BitXor(BitXor(BitOr(BitSHRN(w[t-15+1],7),BitSHLN(w[t-15+1],32-7)),BitOr(BitSHRN(w[t-15+1],18),BitSHLN(w[t-15+1],32-18))),BitSHRN(w[t-15+1],3))>
					<cfset smsig1 = BitXor(BitXor(BitOr(BitSHRN(w[t-2+1],17),BitSHLN(w[t-2+1],32-17)),BitOr(BitSHRN(w[t-2+1],19),BitSHLN(w[t-2+1],32-19))),BitSHRN(w[t-2+1],10))>
					<cfset w[t+1] = smsig1 + w[t-7+1] + smsig0 + w[t-16+1]>
				</cfif>
				<cfloop condition="(w[t+1] LT -2^31) OR (w[t+1] GE 2^31)">
					<cfset w[t+1] = w[t+1] - Sgn(w[t+1])*2^32>
				</cfloop>

				<cfset bgsig0 = BitXor(BitXor(BitOr(BitSHRN(a,2),BitSHLN(a,32-2)),BitOr(BitSHRN(a,13),BitSHLN(a,32-13))),BitOr(BitSHRN(a,22),BitSHLN(a,32-22)))>
				<cfset bgsig1 = BitXor(BitXor(BitOr(BitSHRN(e,6),BitSHLN(e,32-6)),BitOr(BitSHRN(e,11),BitSHLN(e,32-11))),BitOr(BitSHRN(e,25),BitSHLN(e,32-25)))>
				<cfset ch = BitXor(BitAnd(e,f),BitAnd(BitNot(e),g))>
				<cfset maj = BitXor(BitXor(BitAnd(a,b),BitAnd(a,c)),BitAnd(b,c))>

				<cfset t1 = hh + bgsig1 + ch + k[t+1] + w[t+1]>
				<cfset t2 = bgsig0 + maj>
				<cfset hh = g>
				<cfset g = f>
				<cfset f = e>
				<cfset e = d + t1>
				<cfset d = c>
				<cfset c = b>
				<cfset b = a>
				<cfset a = t1 + t2>

				<cfloop condition="(a LT -2^31) OR (a GE 2^31)">
					<cfset a = a - Sgn(a)*2^32>
				</cfloop>
				<cfloop condition="(e LT -2^31) OR (e GE 2^31)">
					<cfset e = e - Sgn(e)*2^32>
				</cfloop>

			</cfloop>

			<cfset h[1] = h[1] + a>
			<cfset h[2] = h[2] + b>
			<cfset h[3] = h[3] + c>
			<cfset h[4] = h[4] + d>
			<cfset h[5] = h[5] + e>
			<cfset h[6] = h[6] + f>
			<cfset h[7] = h[7] + g>
			<cfset h[8] = h[8] + hh>

			<cfloop index="i" from="1" to="8">
				<cfloop condition="(h[i] LT -2^31) OR (h[i] GE 2^31)">
					<cfset h[i] = h[i] - Sgn(h[i])*2^32>
				</cfloop>
			</cfloop>

		</cfloop>

		<cfloop index="i" from="1" to="8">
			<cfset h[i] = RepeatString("0",8-Len(FormatBaseN(h[i],16))) & UCase(FormatBaseN(h[i],16))>
		</cfloop>

		<cfreturn h[1] & h[2] & h[3] & h[4] & h[5] & h[6] & h[7] & h[8]>
	</cffunction>

</cfcomponent>