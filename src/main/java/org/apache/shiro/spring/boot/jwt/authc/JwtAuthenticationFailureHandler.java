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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.authc.AuthcResponseCode;
import org.apache.shiro.biz.authc.AuthenticationFailureHandler;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.jwt.ShiroJwtMessageSource;
import org.apache.shiro.spring.boot.jwt.exception.ExpiredJwtException;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.exception.NotObtainedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

public class JwtAuthenticationFailureHandler implements AuthenticationFailureHandler {

	protected MessageSourceAccessor messages = ShiroJwtMessageSource.getAccessor();
	private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticationFailureHandler.class);
	
	@Override
	public boolean supports(AuthenticationException ex) {
		return SubjectUtils.isAssignableFrom(ex.getClass(), ExpiredJwtException.class,
				IncorrectJwtException.class, InvalidJwtToken.class, NotObtainedJwtException.class);
	}
	
	@Override
	public void onAuthenticationFailure(AuthenticationToken token, ServletRequest request, ServletResponse response,
			AuthenticationException ex) {
		
		if(LOG.isDebugEnabled()) {
			LOG.debug(ExceptionUtils.getRootCauseMessage(ex));
		}
		
		try {
			
			WebUtils.toHttp(response).setStatus(HttpStatus.SC_BAD_REQUEST);
			response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

			// Jwt过期
			if (ex instanceof ExpiredJwtException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getMsgKey(), ex.getMessage())));
			} 
			// Jwt错误
			else if (ex instanceof IncorrectJwtException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getMsgKey(), ex.getMessage())));
			} 
			// Jwt无效
			else if (ex instanceof InvalidJwtToken) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_INVALID.getMsgKey(), ex.getMessage())));
			}
			// Jwt缺失
			else if (ex instanceof NotObtainedJwtException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getMsgKey(), ex.getMessage())));
			} else {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_FAIL.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_FAIL.getMsgKey())));
			}
		} catch (NoSuchMessageException e) {
			LOG.error(e.getMessage());
		} catch (IOException e) {
			LOG.error(e.getMessage());
		}
		
	}

}
