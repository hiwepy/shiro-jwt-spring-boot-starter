package org.apache.shiro.spring.boot.jwt.authz;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationFilter;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jwt授权 (authorization)过滤器 
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public final class JwtAuthorizationFilter extends AbstracAuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JwtAuthorizationFilter.class);
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		Subject subject = getSubject(request, response); 
		if ((null == subject || !subject.isAuthenticated()) && isJwtSubmission(request, response)) {
			AuthenticationToken token = createJwtToken(request, response);
			try {
				subject = getSubject(request, response);
				subject.login(token);
				return true;
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
