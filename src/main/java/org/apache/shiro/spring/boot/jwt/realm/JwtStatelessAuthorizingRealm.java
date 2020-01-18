package org.apache.shiro.spring.boot.jwt.realm;

import java.util.List;
import java.util.Set;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.jwt.JwtPayloadPrincipal;
import org.apache.shiro.spring.boot.jwt.token.JwtAccessToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.util.CollectionUtils;

import com.github.hiwepy.jwt.JwtPayload.RolePair;
import com.google.common.collect.Sets;

/**
 * JSON Web Token (JWT) Stateless AuthorizingRealm
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class JwtStatelessAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return JwtAccessToken.class;// 此Realm只支持JwtToken
	}
	
	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		JwtPayloadPrincipal principal = (JwtPayloadPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		Set<String> sets = Sets.newHashSet();
		List<RolePair> roles = principal.getRoles();
		if(!CollectionUtils.isEmpty(roles)) {
			for (RolePair role : roles) {
				sets.add(role.getKey());
			}
		}
		// 解析角色并设置
		info.setRoles(sets);
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
