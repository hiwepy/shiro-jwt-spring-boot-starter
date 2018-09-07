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

import javax.crypto.SecretKey;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPayload;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.verifier.ExtendedEd25519Verifier;
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
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JSON Web Token (JWT) with HMAC signature and RSA encryption <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-es256k-signature <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwe-with-shared-key <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt
 */
public class SignedWithEdAndEncryptedWithAESJWTRepository implements JwtNestedRepository<OctetKeyPair, SecretKey> {

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
	public String issueJwt(OctetKeyPair signingKey, SecretKey encryptKey, String jwtId, String subject, String issuer, String audience,
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
	 * @return
	 * @throws AuthenticationException
	 */
	
	@Override
	public String issueJwt(OctetKeyPair signingKey, SecretKey encryptKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws AuthenticationException {

		try {
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(jwtId, subject, issuer, audience, claims, period);
						
			//-------------------- Step 1：EdDSA Signature --------------------
			
			// Request JWS Header with EdDSA JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(signingKey.getKeyID()).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
						
			// Create the EdDSA signer
			JWSSigner signer = new Ed25519Signer(signingKey);
			
			// Compute the EC signature
			signedJWT.sign(signer);
			
			//-------------------- Step 2：AES Encrypt ----------------------
			
			// Request JWT encrypted with DIR and 128-bit AES/GCM
			JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
			
			// Create JWE object with signed JWT as payload
			JWEObject jweObject = new JWEObject( jweHeader, new Payload(signedJWT));
			
			// Create an encrypter with the specified public AES key
			JWEEncrypter encrypter = new DirectEncrypter(encryptKey);
						
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
	public boolean verify(OctetKeyPair signingKey, SecretKey encryptKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Step 1：AES Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with AES key
			jweObject.decrypt(new DirectDecrypter(encryptKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
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
	public JwtPayload getPlayload(OctetKeyPair signingKey, SecretKey encryptKey, String token, boolean checkExpiry)  throws AuthenticationException {
		try {
			
			//-------------------- Step 1：AES Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with AES key
			jweObject.decrypt(new DirectDecrypter(encryptKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			//-------------------- Step 2：Gets The Claims ---------------
			
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
