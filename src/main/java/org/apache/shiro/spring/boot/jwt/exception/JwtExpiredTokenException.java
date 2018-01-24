package org.apache.shiro.spring.boot.jwt.exception;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.token.JWTAuthenticationToken;

@SuppressWarnings("serial")
public class JwtExpiredTokenException extends AuthenticationException {
    
    private JWTAuthenticationToken token;

    public JwtExpiredTokenException(String msg) {
        super(msg);
    }

    public JwtExpiredTokenException(JWTAuthenticationToken token, String msg, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public String token() {
        return this.token.getToken();
    }
}
