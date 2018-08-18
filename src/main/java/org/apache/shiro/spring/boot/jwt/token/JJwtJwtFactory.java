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
package org.apache.shiro.spring.boot.jwt.token;

import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.apache.shiro.biz.utils.StringUtils;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */

public class JJwtJwtFactory implements JwtFactory {

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm
	 * @return
	 */
	@Override
	public String issueJwt(String signingKey,String id, String subject, String issuer, Long period, String roles, String permissions,
			String algorithm) throws Exception {
		long currentTimeMillis = System.currentTimeMillis();
		// 当前时间戳
		byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(signingKey);
		// 秘钥
		JwtBuilder jwt = Jwts.builder();
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
		jwt.setIssuedAt(new Date(currentTimeMillis));
		if (null != period) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period);
			jwt.setExpiration(expiration);
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
		jwt.signWith(SignatureAlgorithm.forName(algorithm), secretKeyBytes);
		return jwt.compact();
	}

}
