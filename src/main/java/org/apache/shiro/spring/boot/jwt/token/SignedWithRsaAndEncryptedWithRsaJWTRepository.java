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
import java.util.Date;
import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPayload;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.time.JwtTimeProvider;
import org.apache.shiro.spring.boot.jwt.verifier.ExtendedRSASSAVerifier;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

import com.google.common.collect.Maps;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * <b> JSON Web Token (JWT) with RSA signature and RSA encryption </b>
 * <p> https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-signature </p>
 * <p> https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption </p>
 * <p> https://www.connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt </p>
 */
public class SignedWithRsaAndEncryptedWithRsaJWTRepository implements JwtKeyPairRepository<RSAKey, RSAKey> {
	
	private JwtTimeProvider timeProvider = JwtTimeProvider.DEFAULT_TIME_PROVIDER;
	
	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey	: Signing key
	 * @param secretKey		: Encryption key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param roles			: The Roles
	 * @param permissions	: The Perms
	 * @param algorithm		: Supported algorithms：
	 * <p> RS256 - RSA PKCS#1 signature with SHA-256 </p>
	 * <p> RS384 - RSA PKCS#1 signature with SHA-384 </p>
	 * <p> RS512 - RSA PKCS#1 signature with SHA-512 </p>
	 * <p> PS256 - RSA PSS signature with SHA-256 </p>
	 * <p> PS384 - RSA PSS signature with SHA-384 </p>
	 * <p> PS512 - RSA PSS signature with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public String issueJwt(RSAKey signingKey, RSAKey secretKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period)  throws AuthenticationException {
		 
		Map<String, Object> claims = Maps.newHashMap();
		claims.put("roles", roles);
		claims.put("perms", permissions);
		
		return this.issueJwt(signingKey, secretKey, jwtId, subject, issuer, audience, claims, algorithm, period);
		
	}

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey	: Signing key
	 * @param secretKey		: Encryption key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param claims		: Jwt Claims
	 * @param algorithm		: Supported algorithms：
	 * <p> RS256 - RSA PKCS#1 signature with SHA-256 </p>
	 * <p> RS384 - RSA PKCS#1 signature with SHA-384 </p>
	 * <p> RS512 - RSA PKCS#1 signature with SHA-512 </p>
	 * <p> PS256 - RSA PSS signature with SHA-256 </p>
	 * <p> PS384 - RSA PSS signature with SHA-384 </p>
	 * <p> PS512 - RSA PSS signature with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public String issueJwt(RSAKey signingKey, RSAKey secretKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws AuthenticationException {
		
		try {
			
			//-------------------- Step 1：Get ClaimsSet --------------------
			
			// Prepare JWT with claims set
			JWTClaimsSet.Builder builder = NimbusdsUtils.claimsSet(jwtId, subject, issuer, audience, claims, period);
			// 签发时间
			long currentTimeMillis = this.getTimeProvider().now();
			Date now = new Date(currentTimeMillis);
			builder.issueTime(now);
			// 有效期起始时间
			builder.notBeforeTime(now);
			// Token过期时间
			if (period >= 0) {
				// 有效时间
				Date expiration = new Date(currentTimeMillis + period );
				builder.expirationTime(expiration);
			}
			JWTClaimsSet claimsSet = builder.build();
			
			//-------------------- Step 2：RSA Signature --------------------
			
			// Request JWS Header with RSA JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
			
			// Create RSA-signer with the private key
			JWSSigner signer = new RSASSASigner(signingKey);
			
			// Compute the RSA signature
			signedJWT.sign(signer);
			
			//-------------------- Step 3：RSA Encrypt ----------------------
			
			// Request JWT encrypted with RSA-OAEP-256 and 256-bit AES/GCM
			JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
			
			// Create JWE object with signed JWT as payload
			JWEObject jweObject = new JWEObject( jweHeader, new Payload(signedJWT));
			
			// Create an encrypter with the specified public RSA key
			JWEEncrypter encrypter = new RSAEncrypter(secretKey.toPublicJWK());
						
			// Do the actual encryption
			jweObject.encrypt(encrypter);
			
			// Serialise to JWE compact form
			return jweObject.serialize();
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
	 * @param secretKey 	: 
	 * <p>If the jws was encrypted with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was encrypted with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return If Validity
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public boolean verify(RSAKey signingKey, RSAKey secretKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Step 1：RSA Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with private key
			jweObject.decrypt(new RSADecrypter(secretKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			//-------------------- Step 2：RSA Verify --------------------
			
			// Create RSA verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedRSASSAVerifier(signingKey, signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new RSASSAVerifier(signingKey) ;
			
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
	 * @param secretKey 	: 
	 * <p>If the jws was encrypted with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was encrypted with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p>
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return JwtPlayload {@link JwtPayload}
	 * @throws AuthenticationException When Authentication Exception
	 */
	@Override
	public JwtPayload getPlayload(RSAKey signingKey, RSAKey secretKey, String token, boolean checkExpiry)  throws AuthenticationException {
		try {
			
			//-------------------- Step 1：RSA Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with private key
			jweObject.decrypt(new RSADecrypter(secretKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			//-------------------- Step 2：RSA Verify --------------------
			
			// Create RSA verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedRSASSAVerifier(signingKey, signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new RSASSAVerifier(signingKey) ;
			
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
	
	public JwtTimeProvider getTimeProvider() {
		return timeProvider;
	}

	public void setTimeProvider(JwtTimeProvider timeProvider) {
		this.timeProvider = timeProvider;
	}
 
}
