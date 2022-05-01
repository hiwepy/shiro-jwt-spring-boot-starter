package org.apache.shiro.spring.boot.jwt.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.jwt.token.JwtAuthorizationToken;

/**
 * JSON Web Token (JWT) Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class JwtStatefulAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return JwtAuthorizationToken.class;// 此Realm只支持JwtToken
	}

}
