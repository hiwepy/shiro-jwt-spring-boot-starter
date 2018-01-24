package org.apache.shiro.spring.boot.jwt;

import org.apache.shiro.biz.principal.Principal;

public class TokenResponse {

    public TokenResponse() {
    }

    public TokenResponse(Principal user, String token) {
        this.user = user;
        this.token = token;
    }

    private String token;

    private Principal user;

    public String getToken() {
        return token;
    }

    public Principal getUser() {
        return user;
    }

}
