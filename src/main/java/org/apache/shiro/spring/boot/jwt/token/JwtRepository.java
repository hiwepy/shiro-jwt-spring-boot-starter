package org.apache.shiro.spring.boot.jwt.token;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

public interface JwtRepository<S>{

	public abstract String issueJwt(S signingKey, String id, String subject, String issuer, Long period,
			String roles, String permissions, String algorithm) throws AuthenticationException;

	public abstract boolean verify(S signingKey, String token, boolean checkExpiry) throws AuthenticationException;
	
	public abstract JwtPlayload getPlayload(S signingKey, String token, boolean checkExpiry) throws AuthenticationException;
	
}
