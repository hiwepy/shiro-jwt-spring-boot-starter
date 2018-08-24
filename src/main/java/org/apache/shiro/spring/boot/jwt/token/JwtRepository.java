package org.apache.shiro.spring.boot.jwt.token;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepository;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

public interface JwtRepository extends ShiroPrincipalRepository<ShiroPrincipal> {

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
	public abstract String issueJwt(String signingKey, String id, String subject, String issuer, Long period,
			String roles, String permissions, String algorithm) throws AuthenticationException;

	
	public abstract JwtPlayload getPlayload(String signingKey, String jwt) throws AuthenticationException;
	
	/**
	 * TODO
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @param token
	 * @return
	 */
	
	public abstract boolean valideJwt(String signingKey, String token) throws AuthenticationException;
	
}
