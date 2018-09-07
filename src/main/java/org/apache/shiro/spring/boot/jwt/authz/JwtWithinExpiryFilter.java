package org.apache.shiro.spring.boot.jwt.authz;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.subject.Subject;

/**
 * Jwt有效期检查过滤器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtWithinExpiryFilter extends JwtAuthorizationFilter {
	
	@Override
	protected boolean onAccessSuccess(Object mappedValue, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		// 响应成功状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "success");
		data.put("message", "JWT within validity period.");
		WebUtils.writeJSONString(response, data);
		return false;
	}
	
}
