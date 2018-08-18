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
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.spring.boot.jwt.token.StatelessToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;

/**
 * 扩展自DefaultWebSubjectFactory,对于无状态的JSON Web Token (JWT)不创建session
 */
public class JwtSubjectFactory extends DefaultWebSubjectFactory { 
	
	private final DefaultSessionStorageEvaluator storageEvaluator;
	
	/**
	 * DefaultSessionStorageEvaluator是否持久化SESSION的开关 
	 */
	public JwtSubjectFactory(DefaultSessionStorageEvaluator storageEvaluator){
		this.storageEvaluator = storageEvaluator;
	}
	
	/**
	 * 是否无状态令牌
	 */
	public static boolean isStatelessToken(Object token){
		return token instanceof StatelessToken;
	}
	
    public Subject createSubject(SubjectContext context) { 
    	this.storageEvaluator.setSessionStorageEnabled(Boolean.TRUE);
    	AuthenticationToken token = context.getAuthenticationToken();
    	if(isStatelessToken(token)){
            // 不创建 session 
            context.setSessionCreationEnabled(false);
            // 不持久化session
            this.storageEvaluator.setSessionStorageEnabled(Boolean.FALSE);
    	}
        return super.createSubject(context); 
    }
    
}