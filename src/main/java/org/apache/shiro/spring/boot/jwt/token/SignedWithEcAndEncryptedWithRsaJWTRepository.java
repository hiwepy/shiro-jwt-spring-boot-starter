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
import org.apache.shiro.spring.boot.jwt.verifier.ExtendedECDSAVerifier;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

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
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm: <br/>
	 * 	HS256 - HMAC with SHA-256, requires 256+ bit secret<br/>
     * 	HS384 - HMAC with SHA-384, requires 384+ bit secret<br/>
     * 	HS512 - HMAC with SHA-512, requires 512+ bit secret<br/>
	 * @return JSON Web Token (JWT)
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(ECKey signingKey, RSAKey encryptKey, String id, String subject, String issuer, Long period, String roles,
			String permissions, String algorithm)  throws AuthenticationException {

		try {
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(id, subject, issuer, period, roles, permissions);
						
			//-------------------- Setup 1：ECDSA Signature --------------------
			
			// Request JWS Header with JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
			
			// Create the EC signer
			JWSSigner signer = new ECDSASigner(signingKey);
			
			// Compute the EC signature
			signedJWT.sign(signer);
			
			//-------------------- Setup 2：RSA Encrypt ----------------------
			
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
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		}
		
	}
	
	@Override
	public boolean verify(ECKey signingKey, RSAKey encryptKey, String token, boolean checkExpiry) throws AuthenticationException {

		try {
			
			//-------------------- Setup 1：RSA Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with private key
			jweObject.decrypt(new RSADecrypter(encryptKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			//-------------------- Setup 2：ECDSA Verify --------------------
			
			// Create EC verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedECDSAVerifier(signingKey, signedJWT.getJWTClaimsSet()) : new ECDSAVerifier(signingKey) ;
			
			// Retrieve / verify the JWT claims according to the app requirements
			return signedJWT.verify(verifier);
		} catch (NumberFormatException e) {
			throw new AuthenticationException(e);
		} catch (ParseException e) {
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		}
		
	}
	
	@Override
	public JwtPlayload getPlayload(ECKey signingKey, RSAKey encryptKey, String token)  throws AuthenticationException {
		try {
			
			//-------------------- Setup 1：RSA Decrypt ----------------------
			
			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);
			
			// Decrypt with private key
			jweObject.decrypt(new RSADecrypter(encryptKey));
			
			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			//-------------------- Setup 2：Gets The Claims ---------------
			
			// Retrieve JWT claims
			return NimbusdsUtils.playload(signedJWT.getJWTClaimsSet());
		} catch (ParseException e) {
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		}
		
	}
 
}
