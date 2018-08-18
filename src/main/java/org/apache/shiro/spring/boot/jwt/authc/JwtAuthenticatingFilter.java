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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.AbstractAuthenticatingFilter;
import org.apache.shiro.spring.boot.jwt.authz.JwtAuthorizationFilter;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jwt认证 (authentication)过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthenticatingFilter extends AbstractAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JwtAuthorizationFilter.class);
	
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	
    @Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    	if (isJwtSubmission(request, response)) {
			AuthenticationToken token = createToken(request, response);
			try {
				Subject subject = getSubject(request, response);
				subject.login(token);
				return true;
			} catch (AuthenticationException e) {
				LOG.error("Host {} JWT Authentication Exception : {}", getHost(request), e.getMessage());
				if (WebUtils.isAjaxRequest(request)) {
					WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
					return false;
				}
				saveRequestAndRedirectToLogin(request, response);
			} 
		}
    	if (WebUtils.isAjaxRequest(request)) {
    		WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthentication.");
			return false;
		}
		saveRequestAndRedirectToLogin(request, response);
		return false;
	}
    
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		String host = getHost(request);
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

     
}
