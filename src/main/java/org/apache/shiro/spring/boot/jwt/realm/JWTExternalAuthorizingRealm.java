package org.apache.shiro.spring.boot.jwt.realm;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.protocol.jwt.PrincipalJwtRepository;
import org.apache.shiro.biz.protocol.jwt.token.JWTAuthenticationToken;
import org.apache.shiro.biz.realm.ExternalAuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class JWTExternalAuthorizingRealm extends ExternalAuthorizingRealm {

	@Override
	protected AuthenticationInfo doGetExternalAuthenticationInfo(AuthenticationToken token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// TODO Auto-generated method stub
		return null;
	}

}
