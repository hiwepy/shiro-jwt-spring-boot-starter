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
package org.apache.shiro.spring.boot.jwt.authz;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.authz.AuthorizationFailureHandler;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.jwt.exception.ExpiredJwtException;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.exception.NotObtainedJwtException;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public class JwtAuthorizationFailureHandler implements AuthorizationFailureHandler {

	@Override
	public boolean supports(AuthenticationException ex) {
		return SubjectUtils.supports(ex.getClass(), ExpiredJwtException.class, IncorrectJwtException.class,
				InvalidJwtToken.class, NotObtainedJwtException.class);
	}

	@Override
	public boolean onAuthorizationFailure(Object mappedValue, AuthenticationException e, ServletRequest request,
			ServletResponse response) throws IOException {
		
		//WebUtils.getHttpResponse(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		// Jwt错误
		if (e instanceof IncorrectJwtException) {
			data.put("message", "JWT is incorrect.");
			data.put("token", "incorrect");
		}
		// Jwt无效
		else if (e instanceof InvalidJwtToken) {
			data.put("message", "Invalid JWT value.");
			data.put("token", "invalid");
		}
		// Jwt过期
		else if (e instanceof ExpiredJwtException) {
			data.put("message", "Expired JWT value. " );
			data.put("token", "expiry");
		} else {
			String rootCause = ExceptionUtils.getRootCauseMessage(e);
			data.put("message", StringUtils.hasText(rootCause) ? rootCause : ExceptionUtils.getMessage(e));
		}
		
		WebUtils.toHttp(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error("Unauthentication."));
		
		return false;
	}

}
