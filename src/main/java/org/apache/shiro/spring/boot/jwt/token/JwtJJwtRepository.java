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

import java.util.Arrays;
import java.util.Date;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * 基于JJwt组件实现Jwt相关逻辑
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */

public class JwtJJwtRepository implements JwtRepository {

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm
	 * @return
	 */
	@Override
	public String issueJwt(String signingKey,String id, String subject, String issuer, Long period, String roles, String permissions,
			String algorithm)  throws AuthenticationException {
		
		// 当前时间戳
		long currentTimeMillis = System.currentTimeMillis();
		JwtBuilder jwt = Jwts.builder();
		// Jwt主键ID
		if (StringUtils.hasText(id)) {
			jwt.setId(id);
		}
		// 用户名主题
		jwt.setSubject(subject);
		// 签发者
		if (StringUtils.hasText(issuer)) {
			jwt.setIssuer(issuer);
		}
		// 签发时间
		jwt.setIssuedAt(new Date(currentTimeMillis));
		if (null != period) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period);
			jwt.setExpiration(expiration);
		}
		// 角色
		if (StringUtils.hasText(roles)) {
			jwt.claim("roles", roles);
		}
		// 权限
		if (StringUtils.hasText(permissions)) {
			jwt.claim("perms", permissions);
		}
		// 压缩，可选GZIP
		jwt.compressWith(CompressionCodecs.DEFLATE);
		// 秘钥
		byte[] secretKeyBytes = Base64.decodeBase64(signingKey);
		// 加密设置
		jwt.signWith(SignatureAlgorithm.forName(algorithm), secretKeyBytes);
		return jwt.compact();
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
		JwtPlayload jwtPlayload;
		try {
			Claims claims = Jwts.parser().setSigningKey(Base64.decodeBase64(signingKey))
					.parseClaimsJws(jwt).getBody();
			jwtPlayload = new JwtPlayload();
			jwtPlayload.setTokenId(claims.getId());
			jwtPlayload.setClientId(claims.getSubject());// 用户名
			jwtPlayload.setIssuer(claims.getIssuer());// 签发者
			jwtPlayload.setIssuedAt(claims.getIssuedAt());// 签发时间
			jwtPlayload.setExpiration(claims.getExpiration()); // 过期时间
			jwtPlayload.setNotBefore(claims.getNotBefore());
			jwtPlayload.setAudience(Arrays.asList(claims.getAudience()));// 接收方
			jwtPlayload.setRoles(claims.get("roles", String.class));// 访问主张-角色
			jwtPlayload.setPerms(claims.get("perms", String.class));// 访问主张-权限
		} catch (ExpiredJwtException e) {
			throw new AuthenticationException("JWT 令牌过期:" + e.getMessage());
		} catch (UnsupportedJwtException e) {
			throw new AuthenticationException("JWT 令牌无效:" + e.getMessage());
		} catch (MalformedJwtException e) {
			throw new AuthenticationException("JWT 令牌格式错误:" + e.getMessage());
		} catch (SignatureException e) {
			throw new AuthenticationException("JWT 令牌签名无效:" + e.getMessage());
		} catch (IllegalArgumentException e) {
			throw new AuthenticationException("JWT 令牌参数异常:" + e.getMessage());
		} catch (Exception e) {
			throw new AuthenticationException("JWT 令牌错误:" + e.getMessage());
		}
		return jwtPlayload;
	}


	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param token
	 * @return
	 */
	@Override
	public boolean valideJwt(String signingKey, String token) throws AuthenticationException {
		// TODO Auto-generated method stub
		return false;
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
