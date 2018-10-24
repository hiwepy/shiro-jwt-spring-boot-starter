package org.apache.shiro.spring.boot.jwt.token;

import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPayload;

public interface JwtKeyResolverRepository<S>{
	
	public abstract String issueJwt(S signingKey, String keyId, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws AuthenticationException;

	public abstract String issueJwt(S signingKey, String keyId, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws AuthenticationException;
	
	public abstract boolean verify(String token, boolean checkExpiry) throws AuthenticationException;
	
	public abstract JwtPayload getPlayload(String token, boolean checkExpiry) throws AuthenticationException;
	
}
