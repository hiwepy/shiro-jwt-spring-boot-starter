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

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.web.mgt.SessionCreationEnabledSubjectFactory;
import org.apache.shiro.spring.boot.jwt.token.JwtAuthorizationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;

/**
 * 扩展自StatelessDefaultSubjectFactory,对于无状态的JSON Web Token (JWT)不创建session
 */
public class JwtSubjectFactory extends SessionCreationEnabledSubjectFactory {

	public JwtSubjectFactory(boolean sessionCreationEnabled){
		super(sessionCreationEnabled);
	}

	 @Override
	    public Subject createSubject(SubjectContext context) {

	        boolean authenticated = context.isAuthenticated();

	        if (authenticated) {

	            AuthenticationToken token = context.getAuthenticationToken();

	            if (token != null && token instanceof JwtAuthorizationToken) {
	                final JwtAuthorizationToken clientToken = (JwtAuthorizationToken) token;
	                if (clientToken.isRememberMe()) {
	                    context.setAuthenticated(false);
	                }
	            }

	        }

	        return super.createSubject(context);
	    }

}
