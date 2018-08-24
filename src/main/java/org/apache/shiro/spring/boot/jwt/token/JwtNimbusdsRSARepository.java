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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;
import org.apache.shiro.spring.boot.utils.SecretKeyUtils;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import net.minidev.json.JSONObject;

/**
 * 基于Nimbusds组件实现Jwt相关逻辑
 * @author ： <a href="https://github.com/vindell">vindell</a>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption
 */
public class JwtNimbusdsRSARepository extends JwtNimbusdsRepository {

	/**
	 * TODO
	 * 
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm
	 * @return
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(String publicKey, String id, String subject, String issuer, Long period, String roles,
			String permissions, String algorithm)  throws AuthenticationException {
		// 当前时间戳
		long currentTimeMillis = System.currentTimeMillis();
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		// Jwt主键ID
		if (StringUtils.hasText(id)) {
			builder.jwtID(id);
		}
		// 用户名主题
		builder.subject(subject);
		// 签发者
		if (StringUtils.hasText(issuer)) {
			builder.issuer(issuer);
		}
		// 签发时间
		builder.issueTime(new Date(currentTimeMillis));
		builder.notBeforeTime(new Date(currentTimeMillis));
		if (null != period) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period);
			builder.expirationTime(expiration);
		}
		// 角色
		if (StringUtils.hasText(roles)) {
			builder.claim("roles", roles);
		}
		// 权限
		if (StringUtils.hasText(permissions)) {
			builder.claim("perms", permissions);
		}

		try {
			
			JWTClaimsSet jwtClaims = builder.build();
			
			// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
			JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

			// Create the encrypted JWT object
			EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
			
			// Create an encrypter with the specified public RSA key
			byte[] pubKeyBytes = Base64.decodeBase64(publicKey);
			RSAPublicKey signingKey = (RSAPublicKey) SecretKeyUtils.genPublicKey(SecretKeyUtils.KEY_RSA, pubKeyBytes);
			RSAEncrypter encrypter = new RSAEncrypter(signingKey);

			// Do the actual encryption
			jwt.encrypt(encrypter);
			
			// Serialise to JWT compact form
			return jwt.serialize();
		} catch (KeyLengthException e) {
			throw new AuthenticationException(e);
		} catch (JOSEException e) {
			throw new AuthenticationException(e);
		} catch (GeneralSecurityException e) {
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
	public boolean valideJwt(String signingKey, String token) throws AuthenticationException {
		
		try {
			// 解析token 
			
			

			
			
			JWSObject jwsObject = JWSObject.parse(token);
			//获取到载荷 
			Payload payload = jwsObject.getPayload(); 
			//建立一个解锁密匙 
			JWSVerifier jwsVerifier = new MACVerifier(signingKey); 
			Map<String, Object> resultMap = new HashMap<String, Object>(); 
			//判断token 
			if (jwsObject.verify(jwsVerifier)) { 
				resultMap.put("Result", 0); 
				//载荷的数据解析成json对象。 
				JSONObject jsonObject = payload.toJSONObject(); 
				resultMap.put("data", jsonObject); 
				//判断token是否过期
				if (jsonObject.containsKey("exp")) {
					Long expTime = Long.valueOf(jsonObject.get("exp").toString()); 
					Long nowTime = new Date().getTime();
					//判断是否过期
					if (nowTime > expTime) { 
						//已经过期
						resultMap.clear(); 
						resultMap.put("Result", 2); 
					} 
				} 
			}else { 
				resultMap.put("Result", 1); 
			} 
			
			// TODO Auto-generated method stub
			return false;
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
	public JwtPlayload getPlayload(String privateKey, String token)  throws AuthenticationException {
		JwtPlayload jwtPlayload = null;
		try {
			
			// Parse back
			EncryptedJWT jwt = EncryptedJWT.parse(token);
			
			// Create a decrypter with the specified private RSA key
			byte[] prikeyBytes = Base64.decodeBase64(privateKey);
			PrivateKey signingKey = SecretKeyUtils.genPrivateKey(SecretKeyUtils.KEY_RSA, prikeyBytes);
			RSADecrypter decrypter = new RSADecrypter(signingKey);
			
			// Decrypt
			jwt.decrypt(decrypter);
			
			// Retrieve JWT claims
			JWTClaimsSet jwtClaims = jwt.getJWTClaimsSet();
			
			jwtPlayload = new JwtPlayload();
			jwtPlayload.setTokenId(jwtClaims.getJWTID());
			jwtPlayload.setClientId(jwtClaims.getSubject());// 用户名
			jwtPlayload.setIssuer(jwtClaims.getIssuer());// 签发者
			jwtPlayload.setIssuedAt(jwtClaims.getIssueTime());// 签发时间
			jwtPlayload.setExpiration(jwtClaims.getExpirationTime()); // 过期时间
			jwtPlayload.setNotBefore(jwtClaims.getNotBeforeTime());
			jwtPlayload.setAudience(jwtClaims.getAudience());// 接收方
			jwtPlayload.setRoles(jwtClaims.getStringClaim("roles"));// 访问主张-角色
			jwtPlayload.setPerms(jwtClaims.getStringClaim("perms"));// 访问主张-权限
			
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return jwtPlayload;
	}
 
}
