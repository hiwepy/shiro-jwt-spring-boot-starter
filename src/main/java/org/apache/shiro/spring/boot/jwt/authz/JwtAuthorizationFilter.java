package org.apache.shiro.spring.boot.jwt.authz;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationFilter;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.boot.jwt.exception.IncorrectJwtException;
import org.apache.shiro.spring.boot.jwt.exception.InvalidJwtToken;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jwt授权 (authorization)过滤器
 * 
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthorizationFilter extends AbstracAuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JwtAuthorizationFilter.class);
	protected static final String AUTHORIZATION_PARAM = "token";
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";
    
    private String authorizationHeaderName = AUTHORIZATION_HEADER;
    private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;
	private JwtPayloadRepository jwtPayloadRepository;
	/** If Check JWT Validity. */
	private boolean checkExpiry = false;
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		// 判断是否认证请求  
		if (isJwtSubmission(request, response)) {
			// Step 1、生成无状态Token 
			AuthenticationToken token = createJwtToken(request, response);
			try {
				//Step 2、委托给Realm进行登录  
				Subject subject = getSubject(request, response);
				subject.login(token);
				// Step 3、委托给JwtPayloadRepository进行Token验证
				boolean accessAllowed = getJwtPayloadRepository().verify(token, subject, request, response, isCheckExpiry());
				if (!accessAllowed) {
					throw new InvalidJwtToken("Invalid JWT value.");
				}
				//Step 3、执行授权成功后的函数
				return onAccessSuccess(mappedValue, subject, request, response);
			} catch (AuthenticationException e) {
				//Step 4、执行授权失败后的函数
				return onAccessFailure(mappedValue, e, request, response);
			} 
		}
		
		String mString = String.format("Attempting to access a path which requires authentication.  %s = Authorization Header or %s = Authorization Param or %s = Authorization Cookie  is not present in the request", 
				getAuthorizationHeaderName(), getAuthorizationParamName(), getAuthorizationCookieName());
		if (LOG.isTraceEnabled()) { 
			LOG.trace(mString);
		}
		
		// 响应成功状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		data.put("message", mString);
		// 响应
		WebUtils.writeJSONString(response, data);
		
		return false;
	}

	/**
	 * TODO
	 * @author ：<a href="https://github.com/vindell">vindell</a>
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

		//WebUtils.getHttpResponse(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
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

	protected AuthenticationToken createJwtToken(ServletRequest request, ServletResponse response) {
		String host = WebUtils.getRemoteAddr(request);
		String jwtToken = getAccessToken(request);
		return new JwtToken(host, jwtToken);
	}

    protected boolean isJwtSubmission(ServletRequest request, ServletResponse response) {
    	 String authzHeader = getAccessToken(request);
		return (request instanceof HttpServletRequest) && authzHeader != null;
	}
    
    /**
     * 获取请求的token
     */
    protected String getAccessToken(ServletRequest request) {
    	
    	HttpServletRequest httpRequest = WebUtils.toHttp(request);
        //从header中获取token
        String token = httpRequest.getHeader(getAuthorizationHeaderName());
        //如果header中不存在token，则从参数中获取token
        if (StringUtils.isEmpty(token)) {
            return httpRequest.getParameter(getAuthorizationParamName());
        }
        if (StringUtils.isEmpty(token)) {
            // 从 cookie 获取 token
            Cookie[] cookies = httpRequest.getCookies();
            if (null == cookies || cookies.length == 0) {
                return null;
            }
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(getAuthorizationCookieName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }
        return token;
    }

    public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}
	
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	public String getAuthorizationCookieName() {
		return authorizationCookieName;
	}

	public void setAuthorizationCookieName(String authorizationCookieName) {
		this.authorizationCookieName = authorizationCookieName;
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
