/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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

import org.apache.shiro.biz.web.filter.authc.AbstractLogoutFilter;
import org.apache.shiro.biz.web.filter.authc.LogoutListener;
import org.apache.shiro.subject.Subject;

public class JwtLogoutFilter extends AbstractLogoutFilter {

	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response)
			throws Exception {
		
		Subject subject = getSubject(request, response);
		
		//调用事件监听器
		if(getLogoutListeners() != null && getLogoutListeners().size() > 0){
			for (LogoutListener logoutListener : getLogoutListeners()) {
				logoutListener.beforeLogout(subject, request, response);
			}
		}
		
		// 如果是单点登录，需要重新构造登出的重定向地址
		if(this.isCasLogin()){
			// 重定向到单点登出地址
			issueRedirect(request, response, getCasRedirectUrl(request, response));
			return false;
		}
		
		Exception ex = null;
		boolean result = false;
		try {
			// do real thing
			result = super.preHandle(request, response);
		} catch (Exception e) {
			ex = e;
		}
		
		//调用事件监听器
		if(getLogoutListeners() != null && getLogoutListeners().size() > 0){
			for (LogoutListener logoutListener : getLogoutListeners()) {
				if(ex != null){
					logoutListener.onLogoutFail(subject, ex);
				}else{
					logoutListener.onLogoutSuccess(request, response);
				}
			}
		}
		
		if(ex != null){
			throw ex;
		}
		
		return result;
	}

}
