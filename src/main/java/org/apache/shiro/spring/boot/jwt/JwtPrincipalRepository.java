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
package org.apache.shiro.spring.boot.jwt;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepository;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;

import com.google.common.collect.Sets;

/**
 * Abstract JSON Web Token (JWT) Principal Repository
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class JwtPrincipalRepository implements ShiroPrincipalRepository<JwtPlayload> {

	 /**
     * If Check JWT Validity.
     */
    private boolean checkExpiry;
	
	public abstract JwtPlayload getPlayload(JwtToken jwtToken, boolean checkExpiry);
	
	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		JwtToken jwtToken = (JwtToken) token;
		
		String jwt = (String) jwtToken.getPrincipal();
			
		JwtPlayload playload = this.getPlayload(jwtToken, isCheckExpiry());
		
		// 如果要使token只能使用一次，此处可以过滤并缓存jwtPlayload.getId()
		// 可以做接收方验证
		return new SimpleAuthenticationInfo(playload, jwt, "JWT");
	}

	@Override
	public Set<String> getRoles(JwtPlayload principal) {
		return Sets.newHashSet(StringUtils.tokenizeToStringArray(principal.getRoles()));
	}

	@Override
	public Set<String> getRoles(Set<JwtPlayload> principals) {
		Set<String> sets = Sets.newHashSet();
		for (JwtPlayload jwtPlayload : principals) {
			sets.addAll(Sets.newHashSet(StringUtils.tokenizeToStringArray(jwtPlayload.getRoles())));
		}
		return sets;
	}

	@Override
	public Set<String> getPermissions(JwtPlayload principal) {
		return Sets.newHashSet(StringUtils.tokenizeToStringArray(principal.getPerms()));
	}

	@Override
	public Set<String> getPermissions(Set<JwtPlayload> principals) {
		Set<String> sets = Sets.newHashSet();
		for (JwtPlayload jwtPlayload : principals) {
			sets.addAll(Sets.newHashSet(StringUtils.tokenizeToStringArray(jwtPlayload.getPerms())));
		}
		return sets;
	}

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

}
