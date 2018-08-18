/*
 * Copyright 2017-2018 the original author(https://github.com/wj596)
 * 
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </p>
 */
package org.apache.shiro.spring.boot.jwt.authz;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jwt Perms权限字符 授权 (authorization)过滤器 
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtPermsAuthorizationFilter extends PermissionsAuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JwtPermsAuthorizationFilter.class);
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	
	@Override
	public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
		Subject subject = getSubject(request, response); 
		if ((null == subject || !subject.isAuthenticated()) && isJwtSubmission(request, response)) {
			AuthenticationToken token = createJwtToken(request, response);
			try {
				subject = getSubject(request, response);
				subject.login(token);
				return this.checkPerms(subject,mappedValue);
			} catch (AuthenticationException e) {
				LOG.error("Host {} JWT Authentication Exception : {}", WebUtils.getRemoteAddr(request), e.getMessage());
				return false;
			}	
		}
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
    
    
}
