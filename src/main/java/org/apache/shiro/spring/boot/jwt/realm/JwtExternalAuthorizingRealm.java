package org.apache.shiro.spring.boot.jwt.realm;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.jwt.JwtPayloadPrincipal;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * JSON Web Token (JWT) External AuthorizingRealm
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class JwtExternalAuthorizingRealm extends AbstractAuthorizingRealm<JwtPayloadPrincipal> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;// 此Realm只支持JwtToken
	}
	
	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		JwtPayloadPrincipal principal = (JwtPayloadPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		info.setRoles(principal.getRoles());
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
