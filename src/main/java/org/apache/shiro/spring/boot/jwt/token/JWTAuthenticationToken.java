package org.apache.shiro.biz.protocol.jwt.token;

import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authc.token.UsernameWithoutPwdToken;

@SuppressWarnings("serial")
public class JWTAuthenticationToken extends UsernameWithoutPwdToken implements DelegateAuthenticationToken, JwtToken  {

	protected String token;
    protected String secret;
    
    public JWTAuthenticationToken(final String username, final String token, final String secret) {
        super(username);
        this.token = token;
        this.secret = secret;
    }
    
    public JWTAuthenticationToken(final String username, final boolean rememberMe, final String token, final String secret) {
        super(username, rememberMe);
        this.token = token;
        this.secret = secret;
    }
    
    public JWTAuthenticationToken(final String username, final boolean rememberMe, final String host,  final String token, final String secret) {
    	super(username, rememberMe, host);
        this.token = token;
        this.secret = secret;
    }
    
    @Override
    public Object getCredentials() {
        return getToken();
    }
    
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
	
}
