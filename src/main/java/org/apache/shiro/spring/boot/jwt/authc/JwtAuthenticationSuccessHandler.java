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
package org.apache.shiro.spring.boot.jwt.authc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponseCode;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.boot.jwt.token.JwtLoginToken;
import org.apache.shiro.subject.Subject;
import org.springframework.http.MediaType;
import org.springframework.util.CollectionUtils;

import com.alibaba.fastjson.JSONObject;


public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private JwtPayloadRepository jwtPayloadRepository;
	/** If Check JWT Validity. */
	private boolean checkExpiry = false;
	private final String EMPTY = "null";
	
	public JwtAuthenticationSuccessHandler() {
	}
	
	public JwtAuthenticationSuccessHandler(JwtPayloadRepository jwtPayloadRepository, boolean checkExpiry) {
		super();
		this.jwtPayloadRepository = jwtPayloadRepository;
		this.checkExpiry = checkExpiry;
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		return SubjectUtils.isAssignableFrom(token.getClass(), JwtLoginToken.class);
	}

	@Override
	public void onAuthenticationSuccess(AuthenticationToken token, ServletRequest request, ServletResponse response,
			Subject subject) {

		try {
			
			Map<String, Object> tokenMap = new HashMap<String, Object>();
			
			tokenMap.put("code", AuthcResponseCode.SC_AUTHC_SUCCESS.getCode());
			tokenMap.put("message", "Authentication Success.");
			tokenMap.put("status", "success");

			Object principal = subject.getPrincipal();
			
			// 账号首次登陆标记
			if(ShiroPrincipal.class.isAssignableFrom(principal.getClass())) {
				ShiroPrincipal securityPrincipal = (ShiroPrincipal) principal;
				// 账号首次登陆标记
				tokenMap.put("initial", securityPrincipal.isInitial());
				tokenMap.put("alias", StringUtils.defaultString(securityPrincipal.getAlias(), EMPTY));
				tokenMap.put("userid", securityPrincipal.getUserid());
				tokenMap.put("userkey", StringUtils.defaultString(securityPrincipal.getUserkey(), EMPTY));
				tokenMap.put("usercode", StringUtils.defaultString(securityPrincipal.getUsercode(), EMPTY));
				tokenMap.put("username", securityPrincipal.getUsername());
				tokenMap.put("userid", StringUtils.defaultString(securityPrincipal.getUserid(), EMPTY));
				tokenMap.put("roleid", StringUtils.defaultString(securityPrincipal.getRoleid(), EMPTY ));
				tokenMap.put("role", StringUtils.defaultString(securityPrincipal.getRole(), EMPTY));
				tokenMap.put("roles", CollectionUtils.isEmpty(securityPrincipal.getRoles()) ? new ArrayList<>() : securityPrincipal.getRoles() );
				tokenMap.put("perms", CollectionUtils.isEmpty(securityPrincipal.getPerms()) ? new ArrayList<>() : securityPrincipal.getPerms());
				tokenMap.put("profile", CollectionUtils.isEmpty(securityPrincipal.getProfile()) ? new HashMap<>() : securityPrincipal.getProfile() );
				tokenMap.put("faced", securityPrincipal.isFace());
				tokenMap.put("faceId", StringUtils.defaultString(securityPrincipal.getFaceId(), EMPTY ));
				// JSON Web Token (JWT)
				tokenMap.put("token", getJwtPayloadRepository().issueJwt(token, subject, request, response));
			} else {
				tokenMap.put("initial", false);
				tokenMap.put("alias", "匿名账户");
				tokenMap.put("userid", EMPTY);
				tokenMap.put("userkey", EMPTY);
				tokenMap.put("usercode", EMPTY);
				tokenMap.put("username", EMPTY);
				tokenMap.put("perms", new ArrayList<>());
				tokenMap.put("roleid", EMPTY);
				tokenMap.put("role", EMPTY);
				tokenMap.put("roles", new ArrayList<>());
				tokenMap.put("restricted", false);
				tokenMap.put("profile", new HashMap<>());
				tokenMap.put("faced", false);
				tokenMap.put("faceId", EMPTY);
				tokenMap.put("token", EMPTY);
			}

			WebUtils.toHttp(response).setStatus(HttpStatus.SC_OK);
			response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
			JSONObject.writeJSONString(response.getWriter(), tokenMap);
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

}
