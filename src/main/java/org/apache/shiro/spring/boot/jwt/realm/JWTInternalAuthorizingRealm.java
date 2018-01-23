package org.apache.shiro.biz.protocol.jwt.realm;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.protocol.jwt.PrincipalJwtRepository;
import org.apache.shiro.biz.protocol.jwt.token.JWTAuthenticationToken;
import org.apache.shiro.biz.realm.InternalAuthorizingRealm;
import org.apache.shiro.util.ByteSource;

public class JWTInternalAuthorizingRealm extends InternalAuthorizingRealm {

	@Override
	protected DelegateAuthenticationToken createDelegateAuthenticationToken(AuthenticationToken token) {
		return (JWTAuthenticationToken) token;
	}

	@Override
	protected AuthenticationInfo doGetInternalAuthenticationInfo(AuthenticationToken token) {

		SimpleAccount account = null;
		if (getRepository() instanceof PrincipalJwtRepository) {

			PrincipalJwtRepository jwtRepository = (PrincipalJwtRepository) getRepository();
			JWTAuthenticationToken upToken = (JWTAuthenticationToken) token;

			// do real thing
			// new delegate authentication token and invoke doAuthc method
			DelegateAuthenticationInfo delegateAuthcInfo = getRepository()
					.getAuthenticationInfo(this.createDelegateAuthenticationToken(token));
			if (delegateAuthcInfo != null && jwtRepository.validateToken(upToken.getToken())) {
				account = new SimpleAccount(delegateAuthcInfo.getPrincipal(), delegateAuthcInfo.getCredentials(),
						ByteSource.Util.bytes(delegateAuthcInfo.getCredentialsSalt()), getName());
			}

		}
		return account;

	}

}
