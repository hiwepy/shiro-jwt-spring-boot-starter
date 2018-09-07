package org.apache.shiro.spring.boot.jwt.authz;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.subject.Subject;

/**
 * Jwt有效期检查过滤器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtWithinExpiryFilter extends JwtAuthorizationFilter {
	
	@Override
	protected boolean onAccessSuccess(Object mappedValue, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		return true;
	}
	
}
