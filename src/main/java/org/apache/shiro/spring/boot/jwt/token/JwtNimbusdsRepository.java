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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;

import net.minidev.json.JSONObject;

/**
 * 基于Nimbusds组件实现Jwt相关逻辑
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtNimbusdsRepository implements JwtRepository {

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
	public String issueJwt(String signingKey, String id, String subject, String issuer, Long period, String roles,
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
		
		JWTClaimsSet jwtClaims = builder.build();
		
		/*
         * JWSHeader参数：1.加密算法法则,2.类型，3.。。。。。。。
         * 一般只需要传入加密算法法则就可以。
         * 这里则采用HS256
         * JWSAlgorithm类里面有所有的加密算法法则，直接调用。
         */
		JWSHeader header = new JWSHeader(JWSAlgorithm.parse(algorithm));
		
		//建立一个载荷Payload
		Payload payload = new Payload(jwtClaims.toJSONObject());
		//将头部和载荷结合在一起
		JWSObject jwsObject = new JWSObject(header, payload);

		try {
			//建立一个密匙
			JWSSigner signer = new MACSigner(signingKey);
			//签名
			jwsObject.sign(signer);
			//生成token
			// Output in URL-safe format
			return jwsObject.serialize();
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
	public JwtPlayload getPlayload(String signingKey, String jwt)  throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
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
