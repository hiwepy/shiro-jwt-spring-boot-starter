package org.apache.shiro.spring.boot.jwt.token;

public interface JwtFactory {

	/**
	 * 
	 * 生成jwt签名
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @param signingKey
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm
	 * @return
	 * @throws Exception
	 */
	public abstract String issueJwt(String signingKey, String id, String subject, String issuer, Long period,
			String roles, String permissions, String algorithm) throws Exception;
	
}
