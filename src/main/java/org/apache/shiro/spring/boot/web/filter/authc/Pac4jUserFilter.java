package org.apache.shiro.spring.boot.web.filter.authc;

import javax.servlet.ServletRequest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.util.WebUtils;
import org.pac4j.core.context.Pac4jConstants;

/**
 * 
 * @className	： Pac4jUserFilter
 * @description	： 通过默认的CallbackFilter登录成功以后,会直接redirectToOriginallyRequestedUrl,
 * 但是在pac4j里面没有再去读取被shiro userfilter检测到未登录后存在session中的SavedRequest,
 * 而是读取org.pac4j.core.context.Pac4jConstants#REQUESTED_URL,因此重写UserFilter中的saveRequest适配pac4j
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年1月22日 下午2:59:17
 * @version 	V1.0
 */
public class Pac4jUserFilter extends org.apache.shiro.web.filter.authc.UserFilter {
	
	@Override
	protected void saveRequest(ServletRequest request) {
		// 还是先执行着shiro自己的方法
		super.saveRequest(request);
		Session session = SecurityUtils.getSubject().getSession();
		session.setAttribute(Pac4jConstants.REQUESTED_URL, WebUtils.toHttp(request).getRequestURI());
	}
	
}
