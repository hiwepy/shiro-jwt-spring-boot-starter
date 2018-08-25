/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.utils;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * TODO
 * 
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */

public class JJwtUtils {

	public static final String ROLE_REFRESH_TOKEN = "ROLE_REFRESH_TOKEN";
	public static final String CLAIM_KEY_USER_ID = "user_id";
	public static final String CLAIM_KEY_AUTHORITIES = "scope";
	public static final String CLAIM_KEY_ACCOUNT_ENABLED = "enabled";
	public static final String CLAIM_KEY_ACCOUNT_NON_LOCKED = "non_locked";
	public static final String CLAIM_KEY_ACCOUNT_NON_EXPIRED = "non_expired";

	public static String genToken(String signatureAlgorithm, String base64Secret, String subject,
			Map<String, Object> claims, long expiration) {
		return Jwts.builder().setClaims(claims)
				.setSubject(subject) // 设置主题
				.setHeaderParam("typ", "JWT")
				.setId(UUID.randomUUID().toString())
				.setIssuedAt(new Date())
				.setExpiration(generateExpirationDate(expiration))
				.compressWith(CompressionCodecs.DEFLATE)
				.signWith(SignatureAlgorithm.forName(signatureAlgorithm), base64Secret) // 设置算法（必须）
				.compact();
	}

	public static String genToken(String base64Secret, String id, String subject, String issuer, Long period,
			String roles, String permissions, String signatureAlgorithm) {

		// 当前时间戳
		long currentTimeMillis = System.currentTimeMillis();
		JwtBuilder jwt = Jwts.builder();
		// Jwt主键ID
		if (StringUtils.hasText(id)) {
			jwt.setId(id);
		}
		// 用户名主题
		jwt.setSubject(subject);
		// 签发者
		if (StringUtils.hasText(issuer)) {
			jwt.setIssuer(issuer);
		}
		// 签发时间
		Date now = new Date(currentTimeMillis);
		jwt.setIssuedAt(now);
		// Token过期时间
		if (null != period) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period);
			jwt.setExpiration(expiration).setNotBefore(now);
		}
		// 角色
		if (StringUtils.hasText(roles)) {
			jwt.claim("roles", roles);
		}
		// 权限
		if (StringUtils.hasText(permissions)) {
			jwt.claim("perms", permissions);
		}
		// 压缩，可选GZIP
		jwt.compressWith(CompressionCodecs.DEFLATE);
		// 加密设置
		jwt.signWith(SignatureAlgorithm.forName(signatureAlgorithm), base64Secret);
		return jwt.compact();
	}

	public static JwtPlayload playload(String base64Secret, String token) throws ParseException {

		Claims claims = parseJWT(base64Secret, token);

		JwtPlayload jwtPlayload = new JwtPlayload();
		jwtPlayload.setTokenId(claims.getId());
		jwtPlayload.setClientId(claims.getSubject());// 用户名
		jwtPlayload.setIssuer(claims.getIssuer());// 签发者
		jwtPlayload.setIssuedAt(claims.getIssuedAt());// 签发时间
		jwtPlayload.setExpiration(claims.getExpiration()); // 过期时间
		jwtPlayload.setNotBefore(claims.getNotBefore());
		jwtPlayload.setAudience(Arrays.asList(claims.getAudience()));// 接收方
		jwtPlayload.setRoles(claims.get("roles", String.class));// 访问主张-角色
		jwtPlayload.setPerms(claims.get("perms", String.class));// 访问主张-权限

		return jwtPlayload;
	}

	public static Claims parseJWT(String base64Secret, String token) {
		Claims claims;
		try {
			// 解析jwt串 :其中parseClaimsJws验证jwt字符串失败可能会抛出异常，需要捕获异常
			claims = Jwts.parser().setSigningKey(base64Secret).parseClaimsJws(token).getBody(); // 得到body后我们可以从body中获取我们需要的信息
		} catch (Exception e) {
			// jwt 解析错误
			claims = null;
		}
		return claims;
	}

	public String genAccessToken(String signatureAlgorithm, String base64Secret, String subject,
			Map<String, Object> claims, long access_token_expiration) {
		return genToken(signatureAlgorithm, base64Secret, subject, claims, access_token_expiration);
	}

	public String genRefreshToken(String signatureAlgorithm, String base64Secret, String subject,
			Map<String, Object> claims, long refresh_token_expiration) {
		return genToken(signatureAlgorithm, base64Secret, subject, claims, refresh_token_expiration);
	}

	public Boolean canTokenBeRefreshed(String base64Secret, String token, Date lastPasswordReset) {
		final Date created = getCreatedDateFromToken(base64Secret, token);
		return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset) && (!isTokenExpired(base64Secret, token));
	}

	public String refreshToken(String signatureAlgorithm, String base64Secret, String token,
			long access_token_expiration) {
		String refreshedToken;
		try {
			final Claims claims = parseJWT(base64Secret, token);
			Iterator<Entry<String, Object>> ite = claims.entrySet().iterator();
			Map<String, Object> claimMap = new HashMap<String, Object>();
			while (ite.hasNext()) {
				Entry<String, Object> entry = ite.next();
				claimMap.put(entry.getKey(), entry.getValue());
			}

			refreshedToken = genAccessToken(signatureAlgorithm, base64Secret, claims.getSubject(), claimMap,
					access_token_expiration);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	public long getUserIdFromToken(String base64Secret, String token) {
		long userId;
		try {
			final Claims claims = parseJWT(base64Secret, token);
			userId = (Long) claims.get(CLAIM_KEY_USER_ID);
		} catch (Exception e) {
			userId = 0;
		}
		return userId;
	}

	public String getUsernameFromToken(String base64Secret, String token) {
		String username;
		try {
			final Claims claims = parseJWT(base64Secret, token);
			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}

	public Date getCreatedDateFromToken(String base64Secret, String token) {
		Date created;
		try {
			final Claims claims = parseJWT(base64Secret, token);
			created = claims.getIssuedAt();
		} catch (Exception e) {
			created = null;
		}
		return created;
	}

	public static Date getExpirationDateFromToken(String base64Secret, String token) {
		Date expiration;
		try {
			final Claims claims = parseJWT(base64Secret, token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;
	}

	public static Date generateExpirationDate(long expiration) {
		return new Date(System.currentTimeMillis() + expiration * 1000);
	}

	public static Boolean isTokenExpired(String base64Secret, String token) {
		final Date expiration = getExpirationDateFromToken(base64Secret, token);
		return expiration.before(new Date());
	}

	public static Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	}

}
