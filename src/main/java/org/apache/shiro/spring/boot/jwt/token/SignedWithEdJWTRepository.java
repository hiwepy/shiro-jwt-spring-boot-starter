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
import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPayload;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.verifier.ExtendedEd25519Verifier;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

import com.google.common.collect.Maps;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JSON Web Token (JWT) with EdDSA / Ed25519 signature <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-es256k-signature
 */
public class SignedWithEdJWTRepository implements JwtRepository<OctetKeyPair> {
	
	/**
	 * 
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param jwtId
	 * @param subject
	 * @param issuer
	 * @param roles
	 * @param permissions
	 * @param algorithm: Ed25519
	 * @param period
	 * @return JSON Web Token (JWT)
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(OctetKeyPair signingKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period)  throws AuthenticationException {
		
		Map<String, Object> claims = Maps.newHashMap();
		claims.put("roles", roles);
		claims.put("perms", permissions);
		
		return this.issueJwt(signingKey, jwtId, subject, issuer, audience, claims, algorithm, period);
		
	}
	

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey
	 * @param jwtId
	 * @param subject
	 * @param issuer
	 * @param claims
	 * @param algorithm: Ed25519
	 * @param period
	 * @return
	 * @throws AuthenticationException
	 */
	
	@Override
	public String issueJwt(OctetKeyPair signingKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws AuthenticationException {
		try {
			
			//-------------------- Step 1：Get ClaimsSet --------------------
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(jwtId, subject, issuer, audience, claims, period);
						
			//-------------------- Step 2：EdDSA Signature --------------------
			
			// Request JWS Header with EdDSA JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(signingKey.getKeyID()).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
						
			// Create the EdDSA signer
			JWSSigner signer = new Ed25519Signer(signingKey);
			
			// Compute the EC signature
			signedJWT.sign(signer);
			
			// Serialize the JWS to compact form
			return signedJWT.serialize();
		} catch (KeyLengthException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new IncorrectJwtException(e);
		}
	}


	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param token
	 * @return
	 */
	@Override
	public boolean verify(OctetKeyPair signingKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its EdDSA signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：EdDSA Verify --------------------
			
			// Create Ed25519 verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedEd25519Verifier(signingKey.toPublicJWK(), signedJWT.getJWTClaimsSet()) : new Ed25519Verifier(signingKey.toPublicJWK());
			
			// Retrieve / verify the JWT claims according to the app requirements
			return signedJWT.verify(verifier);
		} catch (IllegalStateException e) {
			throw new IncorrectJwtException(e);
		} catch (NumberFormatException e) {
			throw new IncorrectJwtException(e);
		} catch (ParseException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new InvalidJwtToken(e);
		}
	}

	@Override
	public JwtPayload getPlayload(OctetKeyPair signingKey, String token, boolean checkExpiry)  throws AuthenticationException {
		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its EdDSA signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：EdDSA Verify --------------------
			
			// Create Ed25519 verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedEd25519Verifier(signingKey.toPublicJWK(), signedJWT.getJWTClaimsSet()) : new Ed25519Verifier(signingKey.toPublicJWK());
						
			// Retrieve / verify the JWT claims according to the app requirements
			if(!signedJWT.verify(verifier)) {
				throw new AuthenticationException(String.format("Invalid JSON Web Token (JWT) : %s", token));
			}
			
			//-------------------- Step 3：Gets The Claims ---------------
						
			// Retrieve JWT claims
			return NimbusdsUtils.payload(signedJWT.getJWTClaimsSet());
		} catch (IllegalStateException e) {
			throw new IncorrectJwtException(e);
		} catch (NumberFormatException e) {
			throw new IncorrectJwtException(e);
		} catch (ParseException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new InvalidJwtToken(e);
		}
	}

}
