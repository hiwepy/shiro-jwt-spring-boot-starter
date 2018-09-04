package org.apache.shiro.spring.boot.jwt.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.jwt.JwtPayload;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;

/**
 * JSON Web Token (JWT) Internal AuthorizingRealm
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtInternalAuthorizingRealm extends AbstractAuthorizingRealm<JwtPayload> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;// 此Realm只支持JwtToken
	}

}
