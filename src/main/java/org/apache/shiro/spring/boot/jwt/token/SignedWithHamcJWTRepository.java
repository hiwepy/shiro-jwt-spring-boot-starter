/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.jwt.token;

import java.text.ParseException;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;
import org.apache.shiro.spring.boot.jwt.verifier.ExtendedMACVerifier;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JSON Web Token (JWT) with HMAC signature <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-hmac
 */
public class SignedWithHamcJWTRepository implements JwtRepository<String> {

	/**
	 * 
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm ： <br/>
     * 	HS256 - HMAC with SHA-256, requires 256+ bit secret<br/>
     * 	HS384 - HMAC with SHA-384, requires 384+ bit secret<br/>
     * 	HS512 - HMAC with SHA-512, requires 512+ bit secret<br/>
	 * @return JSON Web Token (JWT)
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(String signingKey, String id, String subject, String issuer, Long period, String roles,
			String permissions, String algorithm)  throws AuthenticationException {
		
		try {
			
			//-------------------- Step 1：Get ClaimsSet --------------------
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(id, subject, issuer, period, roles, permissions);
			
			//-------------------- Step 2：Hamc Signature --------------------
			
			// Create HMAC signer
			byte[] secret = Base64.decode(signingKey);
			JWSSigner signer = new MACSigner(secret);
			
			// Request JWS Header with HMAC JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.parse(algorithm));
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
			
			// Compute the HMAC signature
			signedJWT.sign(signer);
			
			// Serialize to compact form, produces something like
			// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
			return signedJWT.serialize();
		} catch (KeyLengthException e) {
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		}
		
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param token
	 * @return
	 */
	@Override
	public boolean verify(String signingKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its HMAC
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：Hamc Verify --------------------
			
			// Create HMAC verifier
			byte[] secret = Base64.decode(signingKey);
			JWSVerifier verifier = checkExpiry ? new ExtendedMACVerifier(secret, signedJWT.getJWTClaimsSet()) : new MACVerifier(secret) ;
			
			// Retrieve / verify the JWT claims according to the app requirements
			return signedJWT.verify(verifier);
		} catch (IllegalStateException e) {
			throw new AuthenticationException(e);
		} catch (NumberFormatException e) {
			throw new AuthenticationException(e);
		} catch (ParseException e) {
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		}
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param jwt
	 * @return
	 * @throws Exception
	 */
	
	@Override
	public JwtPlayload getPlayload(String signingKey, String token, boolean checkExpiry)  throws AuthenticationException {
		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its HMAC
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：Hamc Verify --------------------
			
			// Create HMAC verifier
			byte[] secret = Base64.decode(signingKey);
			JWSVerifier verifier = checkExpiry ? new ExtendedMACVerifier(secret, signedJWT.getJWTClaimsSet()) : new MACVerifier(secret) ;
						
			// Retrieve / verify the JWT claims according to the app requirements
			if(!signedJWT.verify(verifier)) {
				throw new AuthenticationException(String.format("Invalid JSON Web Token (JWT) : %s", token));
			}
			
			//-------------------- Step 3：Gets The Claims ---------------
			
			// Retrieve JWT claims
			return NimbusdsUtils.playload(signedJWT.getJWTClaimsSet());
		} catch (IllegalStateException e) {
			throw new AuthenticationException(e);
		} catch (NumberFormatException e) {
			throw new AuthenticationException(e);
		} catch (ParseException e) {
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		}
	}

}
