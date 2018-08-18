package org.apache.shiro.spring.boot.jwt.token;

public interface JwtFactory {

    public abstract String issueJwt(String signingKey,String id, String subject, String issuer, Long period, String roles, String permissions,
    		String algorithm) throws Exception;
}
