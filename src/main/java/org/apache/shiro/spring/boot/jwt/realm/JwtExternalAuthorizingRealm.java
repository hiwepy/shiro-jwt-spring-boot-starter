package org.apache.shiro.spring.boot.jwt.realm;

import java.util.Set;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.JwtPayload;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.PrincipalCollection;

import com.google.common.collect.Sets;

/**
 * JSON Web Token (JWT) External AuthorizingRealm
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class JwtExternalAuthorizingRealm extends AbstractAuthorizingRealm<JwtPayload> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;// 此Realm只支持JwtToken
	}
	
	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		JwtPayload jwtPlayload = (JwtPayload) principals.getPrimaryPrincipal();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		Set<String> roles = Sets.newHashSet(StringUtils.tokenizeToStringArray(jwtPlayload.getRoles()));
		info.setRoles(roles);
		// 解析权限并设置
		Set<String> permissions = Sets.newHashSet(StringUtils.tokenizeToStringArray(jwtPlayload.getPerms()));
		info.setStringPermissions(permissions);
		return info;
	}
	
}
