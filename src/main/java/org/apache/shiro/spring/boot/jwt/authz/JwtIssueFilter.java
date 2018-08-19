package org.apache.shiro.spring.boot.jwt.authz;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.jwt.token.JwtFactory;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;

import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.Maps;

/**
 * Jwt 签发 (issue)过滤器 
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public final class JwtIssueFilter extends AccessControlFilter {

	private JwtFactory jwtFactory;
	private String signingKey;
	private String issuer;
	
	@Override
	public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		
		Subject subject = SecurityUtils.getSubject();
		if (subject == null || !subject.isAuthenticated()) {
			
			// 签发一个Json Web Token
	        // 令牌ID=uuid，用户=clientKey，签发者=clientKey
	        // token有效期=1分钟，用户角色=null,用户权限=create,read,update,delete
	        String jwt = jwtFactory.issueJwt(signingKey, UUID.randomUUID().toString(), "", 
	                                    "token-server", 60000l, null, "create,read,update,delete");
	        
	        Map<String,Object> data = Maps.newHashMap();
	        data.put("status", HttpStatus.SC_OK);
	        data.put("jwt", jwt);
			
			if (WebUtils.isAjaxRequest(request)) {
				// 响应成功状态信息
		        WebUtils.writeJSONString(response, data);
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
