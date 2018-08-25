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
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;
import org.apache.shiro.spring.boot.utils.NimbusdsUtils;

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
 * JSON Web Token (JWT) with EC signature <br/>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-ec-signature
 */
public class SignedWithEcJWTRepository implements JwtRepository<ECKey> {

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
	 *  ES256 - EC P-256 DSA with SHA-256 <br/>
     *  ES384 - EC P-384 DSA with SHA-384 <br/>
     *  ES512 - EC P-521 DSA with SHA-512 <br/>
	 * @return JSON Web Token (JWT)
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(ECKey signingKey, String id, String subject, String issuer, Long period, String roles,
			String permissions, String algorithm)  throws AuthenticationException {
		
		try {
			
			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = NimbusdsUtils.claimsSet(id, subject, issuer, period, roles, permissions);
			
			// Request JWS Header with JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
			
			// Create the EC signer
			JWSSigner signer = new ECDSASigner(signingKey);
						
			// Compute the EC signature
			signedJWT.sign(signer);
			
			// Serialize the JWS to compact form
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
	public boolean verify(ECKey signingKey, String token) throws AuthenticationException {

		try {
			
			// On the consumer side, parse the JWS and verify its EC signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			// Create EC verifier
			JWSVerifier verifier = new ECDSAVerifier(signingKey);
			
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

	@Override
	public JwtPlayload getPlayload(ECKey signingKey, String token)  throws AuthenticationException {
		try {
			
			// On the consumer side, parse the JWS and verify its EC
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			// Retrieve JWT claims
			return NimbusdsUtils.playload(signedJWT.getJWTClaimsSet());
		} catch (ParseException e) {
			throw new AuthenticationException(e);
		}
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param token
	 * @return
	 * @throws AuthenticationException
	 */
	
	@Override
	public DelegateAuthenticationInfo getAuthenticationInfo(DelegateAuthenticationToken token)
			throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principal
	 * @return
	 */
	
	@Override
	public Set<String> getRoles(ShiroPrincipal principal) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principals
	 * @return
	 */
	
	@Override
	public Set<String> getRoles(Set<ShiroPrincipal> principals) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principal
	 * @return
	 */
	
	@Override
	public Set<String> getPermissions(ShiroPrincipal principal) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principals
	 * @return
	 */
	
	@Override
	public Set<String> getPermissions(Set<ShiroPrincipal> principals) {
		// TODO Auto-generated method stub
		return null;
	}

}
