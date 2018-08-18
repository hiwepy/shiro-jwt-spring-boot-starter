package org.apache.shiro.spring.boot.jwt.authz;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.jwt.token.JwtFactory;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;

/**
 * Jwt 签发 (issue)过滤器 
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public final class JwtIssueFilter extends AccessControlFilter {

	private JwtFactory jwtFactory;
	
	@Override
	public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		
		Subject subject = SecurityUtils.getSubject();
		if (subject == null || !subject.isAuthenticated()) {
			
			jwtFactory.issueJwt(signingKey, id, subject, issuer, period, roles, permissions, algorithm);
			
			if (WebUtils.isAjaxRequest(request)) {
				// 响应成功状态信息
		        WebUtils.writeJSONString(response, HttpStatus.SC_SESSION_TIMEOUT, "Session Timeout.");
				return false;
			}
		}
		return true;
	}

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return false;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return false;
	}
    
}
