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
import java.util.Date;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * 基于Nimbusds组件的jwt工具对象
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class NimbusdsUtils {

	public static JWTClaimsSet claimsSet(String id, String subject, String issuer, Long period, String roles,
			String permissions) {

		// Current TimeMillis
		long currentTimeMillis = System.currentTimeMillis();

		// Prepare JWT with claims set
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// Jwt主键ID
		if (StringUtils.hasText(id)) {
			builder.jwtID(id);
		}
		// 用户名主题
		builder.subject(subject);
		// 签发者
		if (StringUtils.hasText(issuer)) {
			builder.issuer(issuer);
		}
		// 签发时间
		builder.issueTime(new Date(currentTimeMillis));
		builder.notBeforeTime(new Date(currentTimeMillis));
		if (null != period) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period);
			builder.expirationTime(expiration);
		}
		// 角色
		if (StringUtils.hasText(roles)) {
			builder.claim("roles", roles);
		}
		// 权限
		if (StringUtils.hasText(permissions)) {
			builder.claim("perms", permissions);
		}

		return builder.build();
	}

	public static JwtPlayload playload(JWTClaimsSet jwtClaims) throws ParseException {

		JwtPlayload jwtPlayload = new JwtPlayload();
		jwtPlayload.setTokenId(jwtClaims.getJWTID());
		jwtPlayload.setClientId(jwtClaims.getSubject());// 用户名
		jwtPlayload.setIssuer(jwtClaims.getIssuer());// 签发者
		jwtPlayload.setIssuedAt(jwtClaims.getIssueTime());// 签发时间
		jwtPlayload.setExpiration(jwtClaims.getExpirationTime()); // 过期时间
		jwtPlayload.setNotBefore(jwtClaims.getNotBeforeTime());
		jwtPlayload.setAudience(jwtClaims.getAudience());// 接收方
		jwtPlayload.setRoles(jwtClaims.getStringClaim("roles"));// 访问主张-角色
		jwtPlayload.setPerms(jwtClaims.getStringClaim("perms"));// 访问主张-权限

		return jwtPlayload;
	}

}
