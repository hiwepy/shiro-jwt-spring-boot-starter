/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot.jwt.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 * 
 * @className	： JwtTokenValidationFilter
 * @description	： Jwt Token 有效性验证
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年1月24日 下午5:53:52
 * @version 	V1.0
 */
public class JwtTokenValidationFilter extends AuthenticationFilter {

   /**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";
    
    private String authorizationHeaderName = AUTHORIZATION_HEADER;
    
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
	
		 if (isLoggedAttempt(request, response)) {
	            String jwtToken = getAuthzHeader(request);
	            if (jwtToken != null) {
	            	
	            	
	                return createToken(jwtToken);
	            }
	        }
		
		return super.isAccessAllowed(request, response, mappedValue);
	}
	
	
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		// TODO Auto-generated method stub
		return false;
	}
	
	protected boolean isLoggedAttempt(ServletRequest request, ServletResponse response) {
        String authzHeader = getAuthzHeader(request);
        return authzHeader != null;
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
