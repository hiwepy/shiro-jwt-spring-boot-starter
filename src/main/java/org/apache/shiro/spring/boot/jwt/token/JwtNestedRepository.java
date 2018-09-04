package org.apache.shiro.spring.boot.jwt.token;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPayload;

public interface JwtNestedRepository<S, E> {

	public abstract String issueJwt(S signingKey, E encryptKey, String id, String subject, String issuer, Long period,
			String roles, String permissions, String algorithm) throws AuthenticationException;

	public abstract boolean verify(S signingKey, E encryptKey, String token, boolean checkExpiry)
			throws AuthenticationException;

	public abstract JwtPayload getPlayload(S signingKey, E encryptKey, String token, boolean checkExpiry)
			throws AuthenticationException;
}
