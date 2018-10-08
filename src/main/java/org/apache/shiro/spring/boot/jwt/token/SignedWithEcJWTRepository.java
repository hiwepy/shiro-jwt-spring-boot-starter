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
import org.apache.shiro.spring.boot.jwt.verifier.ExtendedECDSAVerifier;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

import com.google.common.collect.Maps;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * <b> JSON Web Token (JWT) with EC signature </b>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-ec-signature
 */
public class SignedWithEcJWTRepository implements JwtRepository<ECKey> {

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param secretKey		: Signing key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param roles			: The Roles
	 * @param permissions	: The Perms
	 * @param algorithm		: Supported algorithms：
	 * <p> ES256 - EC P-256 DSA with SHA-256 </p>
	 * <p> ES384 - EC P-384 DSA with SHA-384 </p>
	 * <p> ES512 - EC P-521 DSA with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public String issueJwt(ECKey signingKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period)  throws AuthenticationException {
		
		Map<String, Object> claims = Maps.newHashMap();
		claims.put("roles", roles);
		claims.put("perms", permissions);
		
		return this.issueJwt(signingKey, jwtId, subject, issuer, audience, claims, algorithm, period);
		
	}

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey	: Signing key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param claims		: Jwt Claims
	 * @param algorithm		: Supported algorithms：
	 * <p> ES256 - EC P-256 DSA with SHA-256 </p>
	 * <p> ES384 - EC P-384 DSA with SHA-384 </p>
	 * <p> ES512 - EC P-521 DSA with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public String issueJwt(ECKey signingKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims,	String algorithm, long period) throws AuthenticationException {
		try {
			
			//-------------------- Step 1：Get ClaimsSet --------------------
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(jwtId, subject, issuer, audience, claims, period);
			
			//-------------------- Step 2：ECDSA Signature --------------------
			
			// Request JWS Header with JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
			
			// Create the EC signer
			JWSSigner signer = new ECDSASigner(signingKey);
						
			// Compute the EC signature
			signedJWT.sign(signer);
			
			// Serialize the JWS to compact form
			return signedJWT.serialize();
		} catch (IllegalStateException e) {
			throw new IncorrectJwtException(e);
		} catch (KeyLengthException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new IncorrectJwtException(e);
		}
	}

	
	/**
	 * Verify the validity of JWT
	 * @author 				: <a href="https://github.com/vindell">vindell</a>
	 * @param signingKey 	: 
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return If Validity
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public boolean verify(ECKey signingKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its EC signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：ECDSA Verify --------------------
			
			// Create EC verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedECDSAVerifier(signingKey, signedJWT.getJWTClaimsSet()) : new ECDSAVerifier(signingKey) ;
			
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
	
	/**
	 * Parser JSON Web Token (JWT)
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey 	: 
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return JwtPlayload {@link JwtPayload}
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public JwtPayload getPlayload(ECKey signingKey, String token, boolean checkExpiry)  throws AuthenticationException {
		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its EC
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：ECDSA Verify --------------------
			
			// Create EC verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedECDSAVerifier(signingKey, signedJWT.getJWTClaimsSet()) : new ECDSAVerifier(signingKey) ;
			
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
