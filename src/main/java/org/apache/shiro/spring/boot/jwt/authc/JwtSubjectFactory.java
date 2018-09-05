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

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.web.mgt.StatelessDefaultSubjectFactory;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;

/**
 * 扩展自StatelessDefaultSubjectFactory,对于无状态的JSON Web Token (JWT)不创建session
 */
public class JwtSubjectFactory extends StatelessDefaultSubjectFactory { 
	
	public JwtSubjectFactory(DefaultSessionStorageEvaluator storageEvaluator, boolean stateless){
		super(storageEvaluator, stateless);
	}
	
	/**
	 * 是否JWT令牌
	 */
	public static boolean isJwtToken(Object token){
		return token instanceof JwtToken;
	}
	
    public Subject createSubject(SubjectContext context) { 
    	getStorageEvaluator().setSessionStorageEnabled(Boolean.TRUE);
    	context.setSessionCreationEnabled(true);
    	AuthenticationToken token = context.getAuthenticationToken();
    	if(isStateless() && isJwtToken(token)){
            // 不创建 session 
            context.setSessionCreationEnabled(Boolean.FALSE);
            // 不持久化session
            getStorageEvaluator().setSessionStorageEnabled(Boolean.FALSE);
    	}
        return super.createSubject(context); 
    }
    
}