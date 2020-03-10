package org.apache.shiro.spring.boot.jwt.authc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 登录认证绑定的参数对象Model
 */
public class JwtLoginRequest {
	
    private String username;
    private String password;
    private String captcha;
    private boolean rememberMe;

    @JsonCreator
    public JwtLoginRequest(@JsonProperty("username") String username, @JsonProperty("password") String password, @JsonProperty("captcha") String captcha, @JsonProperty("rememberMe") boolean rememberMe) {
        this.username = username;
        this.password = password;
        this.captcha = captcha;
        this.rememberMe = rememberMe;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

	public String getCaptcha() {
		return captcha;
	}

	public void setCaptcha(String captcha) {
		this.captcha = captcha;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isRememberMe() {
		return rememberMe;
	}

	public void setRememberMe(boolean rememberMe) {
		this.rememberMe = rememberMe;
	}
	
}
