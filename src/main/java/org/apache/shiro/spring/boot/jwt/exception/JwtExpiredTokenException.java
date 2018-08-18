package org.apache.shiro.spring.boot.jwt.exception;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.token.StatelessToken;

@SuppressWarnings("serial")
public class JwtExpiredTokenException extends AuthenticationException {
    
    private StatelessToken token;

    public JwtExpiredTokenException(String msg) {
        super(msg);
    }

    public JwtExpiredTokenException(StatelessToken token, String msg, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public String token() {
        return this.token.getToken();
    }
}
