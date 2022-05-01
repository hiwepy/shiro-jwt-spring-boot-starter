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
package org.apache.shiro.spring.boot.jwt;

import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.spring.boot.jwt.token.JwtAuthorizationToken;
import org.apache.shiro.subject.Subject;

import com.github.hiwepy.jwt.JwtPayload;

/**
 * Abstract JSON Web Token (JWT) Payload Repository
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public interface JwtPayloadRepository {

	default String issueJwt(AuthenticationToken token, Subject subject) {
		if(subject.getPrincipal() instanceof ShiroPrincipal) {
			ShiroPrincipal principal = (ShiroPrincipal) subject.getPrincipal();
			return this.issueJwt(principal);
		}
		return "";
	};

	default String issueJwt(ShiroPrincipal principal) {
		return this.issueJwt(principal.getUserid(), principal.getProfile());
	};

	default String issueJwt(String userId, Map<String, Object> profile) {
		return "";
	};

	default boolean verify(AuthenticationToken token, Subject subject, boolean checkExpiry) throws AuthenticationException{
		return false;
	}

	default boolean verify(String token, boolean checkExpiry) throws AuthenticationException{
		return false;
	};

	default JwtPayload getPayload(JwtAuthorizationToken token, boolean checkExpiry){
		return null;
	};

	default JwtPayload getPayload(String token, boolean checkExpiry){
		return null;
	};

}
