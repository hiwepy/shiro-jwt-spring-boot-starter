package org.apache.shiro.spring.boot.jwt.realm;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.spring.boot.jwt.token.JWTAuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;

public class JwtExternalAuthorizingRealm extends Pac4jExternalAuthorizingRealm {

	@Override
    public boolean supports(AuthenticationToken token) {
        return token != null && token instanceof JWTAuthenticationToken;
	}
	
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
