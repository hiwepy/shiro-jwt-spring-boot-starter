package org.apache.shiro.spring.boot.jwt.realm;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.biz.realm.ExternalAuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class JwtExternalAuthorizingRealm extends ExternalAuthorizingRealm {
	
	@Override
	protected AuthenticationInfo doGetExternalAuthenticationInfo(AuthenticationToken token) {
		return null;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		return null;
	}

}
