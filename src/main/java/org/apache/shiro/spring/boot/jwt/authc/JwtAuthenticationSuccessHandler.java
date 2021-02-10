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
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.boot.jwt.token.JwtLoginToken;
import org.apache.shiro.spring.boot.utils.SubjectJwtUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;


public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private JwtPayloadRepository jwtPayloadRepository;
	/** If Check JWT Validity. */
	private boolean checkExpiry = false;
	
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
			
			String tokenString = "";
			// 账号首次登陆标记
			if(ShiroPrincipal.class.isAssignableFrom(subject.getPrincipal().getClass())) {
				// JSON Web Token (JWT)
				tokenString = getJwtPayloadRepository().issueJwt(token, subject, request, response);
			} 
			
			Map<String, Object> tokenMap = SubjectJwtUtils.tokenMap(subject, tokenString);
			
			WebUtils.toHttp(response).setStatus(HttpStatus.SC_OK);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
			JSONObject.writeJSONString(response.getWriter(), tokenMap);
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	@Override
	public int getOrder() {
		return Integer.MAX_VALUE - 1;
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
