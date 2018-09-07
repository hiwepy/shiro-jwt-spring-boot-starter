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
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JSON Web Token (JWT) with HMAC signature and RSA encryption <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-ec-signature <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt
 */
public class SignedWithEcAndEncryptedWithRsaJWTRepository implements JwtNestedRepository<ECKey,RSAKey> {

	/**
	 * @param jwtId
	 * @param subject
	 * @param issuer
	 * @param roles
	 * @param permissions
	 * @param algorithm: <br/>
	 * 	HS256 - HMAC with SHA-256, requires 256+ bit secret<br/>
     * 	HS384 - HMAC with SHA-384, requires 384+ bit secret<br/>
     * 	HS512 - HMAC with SHA-512, requires 512+ bit secret<br/>
     * @param period
	 * @return JSON Web Token (JWT)
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(ECKey signingKey, RSAKey encryptKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period)  throws AuthenticationException {

		Map<String, Object> claims = Maps.newHashMap();
		claims.put("roles", roles);
		claims.put("perms", permissions);
		
		return this.issueJwt(signingKey, encryptKey, jwtId, subject, issuer, audience, claims, algorithm, period);
		
	}
	

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey
	 * @param encryptKey
	 * @param jwtId
	 * @param subject
	 * @param issuer
	 * @param claims
	 * @param algorithm: <br/>
	 * 	HS256 - HMAC with SHA-256, requires 256+ bit secret<br/>
     * 	HS384 - HMAC with SHA-384, requires 384+ bit secret<br/>
     * 	HS512 - HMAC with SHA-512, requires 512+ bit secret<br/>
	 * @param period
	 * @return JSON Web Token (JWT)
	 * @throws AuthenticationException
	 */
	@Override
	public String issueJwt(ECKey signingKey, RSAKey encryptKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws AuthenticationException {
		
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
			
			//-------------------- Step 3：RSA Encrypt ----------------------
			
			// Request JWT encrypted with RSA-OAEP-256 and 256-bit AES/GCM
			JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
			
			// Create JWE object with signed JWT as payload
			JWEObject jweObject = new JWEObject( jweHeader, new Payload(signedJWT));
			
			// Create an encrypter with the specified public RSA key
			JWEEncrypter encrypter = new RSAEncrypter(encryptKey.toPublicJWK());
						
			// Do the actual encryption
			jweObject.encrypt(encrypter);
			
			// Serialise to JWE compact form
			return jweObject.serialize();
		} catch (KeyLengthException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new IncorrectJwtException(e);
		}
	}
	
	@Override
	public boolean verify(ECKey signingKey, RSAKey encryptKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Step 1：RSA Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with private key
			jweObject.decrypt(new RSADecrypter(encryptKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
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
	
	@Override
	public JwtPayload getPlayload(ECKey signingKey, RSAKey encryptKey, String token, boolean checkExpiry)  throws AuthenticationException {
		try {
			
			//-------------------- Step 1：RSA Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with private key
			jweObject.decrypt(new RSADecrypter(encryptKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			
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
