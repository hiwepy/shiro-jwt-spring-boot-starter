/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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
/**
 * 
 */
package org.apache.shiro.spring.boot.jwt.servlet;

import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.web.Parameters;
import org.apache.shiro.biz.web.servlet.AbstractHttpServlet;

import com.google.common.collect.Maps;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * TODO
 * 
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class Authenticate extends AbstractHttpServlet {

	private final String SECRET_KEY = "*(-=4eklfasdfarerf41585fdasf";

	@Override
	public void init(ServletConfig filterConfig) throws ServletException {
		super.init(filterConfig);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		// 每次请求到达，必须调用一次初始化方法，否则可能取得的参数是其他Servlet的参数（如同一个Servlet有多个配置情况下就会出现参数干扰问题）
		Parameters.initialize(getServletConfig());

		String clientKey = req.getParameter("clientKey");

		// 签发一个Json Web Token
		// 令牌ID=uuid，用户=clientKey，签发者=clientKey
		// token有效期=1分钟，用户角色=null,用户权限=create,read,update,delete
		String jwt = issueJwt(UUID.randomUUID().toString(), clientKey, "token-server", 60000l, null,
				"create,read,update,delete");
		Map<String, Object> respond = Maps.newHashMap();
		respond.put("jwt", jwt);

	}

	/**
	 * @param id 令牌ID
	 * @param subject 用户ID
	 * @param issuer 签发人
	 * @param period 有效时间(毫秒)
	 * @param roles 访问主张-角色
	 * @param permissions 访问主张-权限
	 * @param algorithm  加密算法
	 * @return json web token
	 */
	private String issueJwt(String id, String subject, String issuer, Long period, String roles, String permissions,
			SignatureAlgorithm algorithm) {
		long currentTimeMillis = System.currentTimeMillis();
		// 当前时间戳
		byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
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
		jwt.signWith(algorithm, secretKeyBytes);
		return jwt.compact();
	}

}
