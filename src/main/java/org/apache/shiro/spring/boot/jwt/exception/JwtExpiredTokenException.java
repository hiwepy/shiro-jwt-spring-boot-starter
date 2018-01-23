package org.apache.shiro.biz.protocol.jwt.exception;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.protocol.jwt.token.JwtToken;

@SuppressWarnings("serial")
public class JwtExpiredTokenException extends AuthenticationException {
    
    private JwtToken token;

    public JwtExpiredTokenException(String msg) {
        super(msg);
    }

    public JwtExpiredTokenException(JwtToken token, String msg, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public String token() {
        return this.token.getToken();
    }
}
