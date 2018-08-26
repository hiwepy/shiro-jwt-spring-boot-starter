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
import org.apache.shiro.spring.boot.jwt.JwtPlayload;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JSON Web Token (JWT) with RSA signature <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-signature <br/>
 * 私钥签名，公钥验证
 */
public class SignedWithRsaJWTRepository implements JwtRepository<RSAKey> {

	/**
	 * 
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm: <br/>
	 * 	RS256 - RSA PKCS#1 signature with SHA-256 <br/>
	 * 	RS384 - RSA PKCS#1 signature with SHA-384 <br/>
	 * 	RS512 - RSA PKCS#1 signature with SHA-512 <br/>
	 * 	PS256 - RSA PSS signature with SHA-256 <br/>
	 * 	PS384 - RSA PSS signature with SHA-384 <br/>
	 * 	PS512 - RSA PSS signature with SHA-512 <br/>
	 * @return JSON Web Token (JWT)
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(RSAKey signingKey, String id, String subject, String issuer, Long period, String roles,
			String permissions, String algorithm)  throws AuthenticationException {
		
		try {
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(id, subject, issuer, period, roles, permissions);
						
			// Create RSA-signer with the private key
			JWSSigner signer = new RSASSASigner(signingKey);
			
			// Request JWS Header with JWSAlgorithm
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).build();
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			
			// Compute the RSA signature
			signedJWT.sign(signer);
			
			// To serialize to compact form, produces something like
			// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
			// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
			// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
			// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
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
	public boolean verify(RSAKey signingKey, String token) throws AuthenticationException {

		try {
			
			// On the consumer side, parse the JWS and verify its RSA signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			// Create RSA verifier
			JWSVerifier verifier = new RSASSAVerifier(signingKey);
			
			// Retrieve / verify the JWT claims according to the app requirements
			return NimbusdsUtils.verify(signedJWT, verifier);
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
	public JwtPlayload getPlayload(RSAKey signingKey, String token)  throws AuthenticationException {
		try {
			
			// On the consumer side, parse the JWS and verify its HMAC
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			// Retrieve JWT claims
			return NimbusdsUtils.playload(signedJWT.getJWTClaimsSet());
		} catch (ParseException e) {
			throw new AuthenticationException(e);
		}
	}

}
