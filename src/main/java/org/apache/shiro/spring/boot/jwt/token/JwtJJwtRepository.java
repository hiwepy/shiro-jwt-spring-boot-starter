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

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;
import org.apache.shiro.spring.boot.utils.JJwtUtils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * 基于JJwt组件实现Jwt相关逻辑
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */

public class JwtJJwtRepository implements JwtRepository<String> {

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
	public String issueJwt(String base64Secret,String id, String subject, String issuer, Long period, String roles, String permissions,
			String algorithm)  throws AuthenticationException {
		return JJwtUtils.genToken(base64Secret, id, subject, issuer, period, roles, permissions, algorithm);
	}
	
	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param jwt
	 * @return
	 * @throws Exception
	 */
	@Override
	public JwtPlayload getPlayload(String base64Secret, String token)  throws AuthenticationException {
		try {
			return JJwtUtils.playload(base64Secret, token);
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

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param base64Secret
	 * @param token
	 * @return
	 * @throws AuthenticationException
	 */
	
	@Override
	public boolean verify(String base64Secret, String token) throws AuthenticationException {
		// TODO Auto-generated method stub
		return JJwtUtils.isTokenExpired(base64Secret, token);
	}


	
}
