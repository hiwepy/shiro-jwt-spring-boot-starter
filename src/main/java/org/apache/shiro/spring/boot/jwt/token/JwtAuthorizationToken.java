/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import org.apache.shiro.authc.HostAuthenticationToken;

/**
 * JSON Web Token (JWT) Token
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class JwtAuthorizationToken implements HostAuthenticationToken {

	// 客户端IP
	private String host;
	// JSON Web Token (JWT) 令牌
	private String token;

    private final boolean isRememberMe;

	public JwtAuthorizationToken(String host, String token, boolean isRememberMe) {
		this.host = host;
		this.token = token;
		this.isRememberMe = isRememberMe;
	}

	@Override
	public Object getPrincipal() {
		return this.token;
	}

	@Override
	public Object getCredentials() {
		return this.token;
	}

	@Override
	public String getHost() {
		return host;
	}

	public String getToken() {
		return token;
	}

	public boolean isRememberMe() {
		return isRememberMe;
	}

}
