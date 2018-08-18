/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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
/**
 * 
 */
package org.apache.shiro.spring.boot.jwt.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * * JWT令牌 *
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) *
 * @date 2016年6月24日 下午2:55:15
 */
public class JwtToken implements AuthenticationToken {
	
	private String jwt;
	// json web token
	private String host;// 客户端IP

	public JwtToken(String jwt, String host) {
		this.jwt = jwt;
		this.host = host;
	}

	@Override
	public Object getPrincipal() {
		return this.jwt;
	}

	@Override
	public Object getCredentials() {
		return Boolean.TRUE;
	}
	
}
