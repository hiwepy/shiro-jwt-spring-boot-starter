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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.StringUtils;
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
	
	 protected static final String AUTHORIZATION_PARAM = "token";
	 
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";
    
    private String authorizationHeaderName = AUTHORIZATION_HEADER;
    private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;
	private JwtPayloadRepository jwtPayloadRepository;
	/**
	 * If Session Stateless
	 */
	private boolean stateless = false;
	/**
	 * If Check JWT Validity.
	 */
	private boolean checkExpiry = false;
	
	public JwtAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		// 判断是否认证请求  
		if (isJwtSubmission(request, response)) {
			// Step 1、生成无状态Token 
			AuthenticationToken token = createJwtToken(request, response);
			try {
				//Step 2、委托给Realm进行登录  
				Subject subject = getSubject(request, response);
				subject.login(token);
				// Step 3、委托给JwtPayloadRepository进行Token验证
				boolean accessAllowed = getJwtPayloadRepository().verify(token, subject, request, response, isCheckExpiry());
				if (!accessAllowed) {
					throw new InvalidJwtToken("Invalid JWT value.");
				}
				//Step 3、执行授权成功后的函数
				return onAccessSuccess(token, subject, request, response);
			} catch (AuthenticationException e) {
				//Step 4、执行授权失败后的函数
				return onAccessFailure(token, e, request, response);
			} 
		}
		// 非认证请求需要进行权限认证
		return false;
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
		// 2、未授权情况
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
		data.put("status", "success");
		data.put("message", "Authentication Success.");
		data.put("token", jwt);
		// 响应
		WebUtils.writeJSONString(response, data);
		
		// we handled the success , prevent the chain from continuing:
		return false;

	}
	
	@Override
	protected boolean onAccessFailure(AuthenticationToken token, Exception e, ServletRequest request,
			ServletResponse response) {
		
		LOG.error("Host {} JWT Authentication Failure : {}", getHost(request), e.getMessage());
		
		//WebUtils.getHttpResponse(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		// Jwt错误
		if (e instanceof IncorrectJwtException) {
			data.put("message", "JWT is incorrect.");
		} 
		// Jwt无效
		else if (e instanceof InvalidJwtToken) {
			data.put("message", "Invalid JWT value of header name ["+ getAuthorizationHeaderName() + "]. " );
		}
		WebUtils.writeJSONString(response, data);
		return false;
	}
	
	protected AuthenticationToken createJwtToken(ServletRequest request, ServletResponse response) {
		String host = WebUtils.getRemoteAddr(request);
		String jwtToken = getRequestToken(request);
		return new JwtToken(host, jwtToken);
	}

    protected boolean isJwtSubmission(ServletRequest request, ServletResponse response) {
    	 String authzHeader = getRequestToken(request);
		return (request instanceof HttpServletRequest) && authzHeader != null;
	}
    
    /**
     * 获取请求的token
     */
    protected String getRequestToken(ServletRequest request) {
    	
    	HttpServletRequest httpRequest = WebUtils.toHttp(request);
        //从header中获取token
        String token = httpRequest.getHeader(getAuthorizationHeaderName());
        //如果header中不存在token，则从参数中获取token
        if (StringUtils.isEmpty(token)) {
            return httpRequest.getParameter(getAuthorizationParamName());
        }
        if (StringUtils.isEmpty(token)) {
            // 从 cookie 获取 token
            Cookie[] cookies = httpRequest.getCookies();
            if (null == cookies || cookies.length == 0) {
                return null;
            }
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(getAuthorizationCookieName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }
        return token;
    }
    
	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}
	
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	public String getAuthorizationCookieName() {
		return authorizationCookieName;
	}

	public void setAuthorizationCookieName(String authorizationCookieName) {
		this.authorizationCookieName = authorizationCookieName;
	}

	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}

	public boolean isStateless() {
		return stateless;
	}

	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}
	
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}
	
}
