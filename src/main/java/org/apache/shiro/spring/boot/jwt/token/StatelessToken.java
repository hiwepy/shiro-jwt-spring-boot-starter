package org.apache.shiro.spring.boot.jwt.token;

import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authc.token.UsernameWithoutPwdToken;

@SuppressWarnings("serial")
public class StatelessToken extends UsernameWithoutPwdToken implements DelegateAuthenticationToken  {

	protected String token;
    protected String secret;
    
    
    
    @Override
    public Object getCredentials() {
        return getToken();
    }

	@Override
	public char[] getPassword() {
		return null;
	}
    
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
	
	
}
