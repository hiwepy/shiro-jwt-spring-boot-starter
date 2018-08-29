package org.apache.shiro.spring.boot.jwt.token;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

public interface JwtNestedRepository<S,E> {

	/**
	 * 
	 * 生成jwt签名
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @param signingKey
	 * @param id 令牌ID
     * @param subject 用户ID
     * @param issuer 签发人
     * @param period 有效时间(毫秒)
     * @param roles 访问主张-角色
     * @param permissions 访问主张-权限
     * @param algorithm 加密算法
     * @return json web token 
	 * @throws Exception
	 */
	public abstract String issueJwt(S signingKey, E encryptKey, String id, String subject, String issuer, Long period,
			String roles, String permissions, String algorithm) throws AuthenticationException;

	
	public abstract JwtPlayload getPlayload(S signingKey, E encryptKey, String jwt) throws AuthenticationException;
	
	public abstract boolean verify(S signingKey, E encryptKey, String token, boolean checkExpiry) throws AuthenticationException;
	
}
