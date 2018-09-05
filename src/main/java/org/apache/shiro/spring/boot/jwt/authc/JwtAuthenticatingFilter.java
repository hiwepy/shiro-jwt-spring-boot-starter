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
package org.apache.shiro.spring.boot.jwt.authc;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.exception.InvalidAccountException;
import org.apache.shiro.biz.authc.exception.NoneRoleException;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.TrustableRestAuthenticatingFilter;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jwt认证 (authentication)过滤器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthenticatingFilter extends TrustableRestAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticatingFilter.class);
	
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	private JwtPayloadRepository jwtPayloadRepository;

	public JwtAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		// 1、判断是否登录请求 
		if (isLoginRequest(request, response)) {
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
				if (LOG.isTraceEnabled()) {
					LOG.trace(mString);
				}
				WebUtils.writeJSONString(response, HttpServletResponse.SC_BAD_REQUEST, mString);
				return false;
			}
		}
		// 2、判断是否认证请求  
		if (isJwtSubmission(request, response)) {
			//Step 1、生成无状态Token 
			AuthenticationToken token = createJwtToken(request, response);
			try {
				//Step 2、委托给Realm进行登录  
				Subject subject = getSubject(request, response);
				subject.login(token);
				//Step 3、执行授权成功后的函数
				return onAccessSuccess(token, subject, request, response);
			} catch (AuthenticationException e) {
				//Step 4、执行授权失败后的函数
				return onAccessFailure(token, e, request, response);
			} 
		}
		// 3、未授权情况
		else {
			String mString = "Attempting to access a path which requires authentication.  Forwarding to the "
					+ "Authentication url [" + WebUtils.getHttpRequest(request).getRequestURI() + "]";
			if (LOG.isTraceEnabled()) {
				LOG.trace(mString);
			}
			WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, mString);
			return false;
		}
	}

	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {

		// 调用事件监听器
		if (getLoginListeners() != null && getLoginListeners().size() > 0) {
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginSuccess(token, subject, request, response);
			}
		}
		
		// JSON Web Token (JWT)
		String jwt = getJwtPayloadRepository().issueJwt(token, subject, request, response);

		// 响应成功状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", HttpServletResponse.SC_OK);
		data.put("message", "Authentication Success.");
		data.put("token", jwt);
		// 响应
		WebUtils.writeJSONString(response, data);
		
		// we handled the success , prevent the chain from continuing:
		return false;

	}
	
	@Override
	protected void setFailureRespone(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		// 已经超出了重试限制，需要进行提醒
		if (isOverRetryTimes(request, response)) {
			data.put("message", "Over Maximum number of retry to login.");
			data.put("captcha", "required");
		}
		// 验证码错误
		else if (e instanceof IncorrectCaptchaException) {
			data.put("message", "Invalid captcha value.");
			data.put("captcha", "error");
		}
		// Jwt错误
		else if (e instanceof IncorrectJwtException) {
			data.put("message", "JWT is incorrect.");
		}
		// Jwt无效
		else if (e instanceof InvalidJwtToken) {
			data.put("message", "Invalid JWT value.");
		}
		// 账号或密码为空
		else if (e instanceof UnknownAccountException) {
			data.put("message", "Username or password is required.");
		}
		// 账户或密码错误
		else if (e instanceof InvalidAccountException) {
			data.put("message", "Username or password is incorrect, please re-enter.");
		}
		// 账户没有启用
		else if (e instanceof DisabledAccountException) {
			data.put("message", "Account is disabled.");
		}
		// 该用户无所属角色，禁止登录
		else if (e instanceof NoneRoleException) {
			data.put("message", "Username or password is incorrect, please re-enter");
		} else {
			data.put("message", "Authentication Exception.");
		}
		// 导致异常的类型
		data.put(getFailureKeyAttribute(), e.getClass().getName());
		WebUtils.writeJSONString(response, data);
	}

	@Override
	protected boolean onAccessFailure(AuthenticationToken token, Exception e, ServletRequest request,
			ServletResponse response) {
		
		LOG.error("Host {} JWT Authentication Failure : {}", getHost(request), e.getMessage());
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", HttpServletResponse.SC_UNAUTHORIZED);
		// Jwt错误
		if (e instanceof IncorrectJwtException) {
			data.put("message", "JWT is incorrect.");
		} 
		// Jwt无效
		else if (e instanceof InvalidJwtToken) {
			data.put("message", "Invalid JWT value.");
		}
		WebUtils.writeJSONString(response, data);
		return false;
	}
	
	protected AuthenticationToken createJwtToken(ServletRequest request, ServletResponse response) throws IOException {
		String host = WebUtils.getRemoteAddr(request);
		String jwtToken = getAuthzHeader(request);
		return new JwtToken(host, jwtToken);
	}

    protected boolean isJwtSubmission(ServletRequest request, ServletResponse response) {
    	 String authzHeader = getAuthzHeader(request);
		return (request instanceof HttpServletRequest) && authzHeader != null;
	}

    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader(getAuthorizationHeaderName());
    }

	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}
	
	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}
	
}
