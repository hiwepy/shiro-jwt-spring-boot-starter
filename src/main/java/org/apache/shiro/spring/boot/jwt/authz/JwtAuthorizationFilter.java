package org.apache.shiro.spring.boot.jwt.authz;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationFilter;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
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
	private JwtPayloadRepository jwtPayloadRepository;
	  /**
     * If Check JWT Validity.
     */
    private boolean checkExpiry = false;
    
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		
		
		// 2、判断是否认证请求  
		if (isJwtSubmission(request, response)) {
			//Step 1、获取Subject
			Subject subject = getSubject(request, response);
			//Step 2、获取Token值 
			String token = getAuthzHeader(request);
			try {
				//Step 3、委托给JwtPayloadRepository进行Token验证
				boolean accessAllowed = getJwtPayloadRepository().verify(token, isCheckExpiry());
				if(!accessAllowed) {
					throw new InvalidJwtToken("Invalid JWT value.");
				}
				//Step 4、执行授权成功后的函数
				return onAccessSuccess(token, subject, request, response);
			} catch (Exception e) {
				//Step 6、执行授权失败后的函数
				return onAccessFailure(mappedValue, e, request, response);
			} 
		}
		WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthentication.");
		return false;
	}
	
	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param mappedValue
	 * @param e
	 * @param request
	 * @param response
	 * @return
	 */
	@Override
	protected boolean onAccessFailure(Object mappedValue, Exception e, ServletRequest request,
			ServletResponse response) {
		
		LOG.error("Host {} JWT Authentication Failure : {}", getHost(request), e.getMessage());
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", HttpServletResponse.SC_UNAUTHORIZED);
		// Jwt错误
		if (e instanceof IncorrectJwtException) {
			data.put("message", "JWT is incorrect.");
		} 
		// Jwt无效
		else if (e instanceof InvalidJwtToken) {
			data.put("message", "Invalid JWT value.");
		}
		WebUtils.writeJSONString(response, data);
		return false;
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
	
	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}
	
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}
}
