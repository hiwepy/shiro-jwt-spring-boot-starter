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
package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroJwtProperties.PREFIX)
public class ShiroJwtProperties {

	public static final String PREFIX = "shiro.jwt";

	// 默认HMAC签名有效期：1分钟=60000毫秒(ms)
	protected static final Integer DEFAULT_HMAC_PERIOD = 60000;
	// 默认HASH加密算法
	protected static final String DEFAULT_HASH_ALGORITHM_NAME = "MD5";
	// 默认HASH加密盐
	protected static final String DEFAULT_HASH_SALT = "A1B2C3D4efg.5679g8e7d6c5b4a_-=_)(8.";
	// 默认HASH加密迭代次数
	protected static final Integer DEFAULT_HASH_ITERATIONS = 2;

	// 默认JWT加密算法
	protected static final String DEFAULT_HMAC_ALGORITHM_NAME = "HmacMD5";
	// HASH加密算法
	public static final String HASH_ALGORITHM_NAME_MD5 = "MD5";
	public static final String HASH_ALGORITHM_NAME_SHA1 = "SHA-1";
	public static final String HASH_ALGORITHM_NAME_SHA256 = "SHA-256";
	public static final String HASH_ALGORITHM_NAME_SHA512 = "SHA-512";
	// HMACA签名算法
	public static final String HMAC_ALGORITHM_NAME_MD5 = "HmacMD5";// 128位
	public static final String HMAC_ALGORITHM_NAME_SHA1 = "HmacSHA1";// 126
	public static final String HMAC_ALGORITHM_NAME_SHA256 = "HmacSHA256";// 256
	public static final String HMAC_ALGORITHM_NAME_SHA512 = "HmacSHA512";// 512

	/**
	 * Enable Shiro JWT.
	 */
	private boolean enabled = false;

	/**
	 * If Check JWT Validity.
	 */
	private boolean checkExpiry;

	/**
	 * {@link JwtToken} will expire after this time.
	 */
	private Long tokenExpirationTime;

	/**
	 * Token issuer.
	 */
	private String tokenIssuer;

	/**
	 * Key is used to sign {@link JwtToken}.
	 */
	private String tokenSigningKey;

	/**
	 * {@link JwtToken} can be refreshed during this timeframe.
	 */
	private Integer refreshTokenExpTime;

	private Long access_token_expiration;

	private Long refresh_token_expiration;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

	public Long getTokenExpirationTime() {
		return tokenExpirationTime;
	}

	public void setTokenExpirationTime(Long tokenExpirationTime) {
		this.tokenExpirationTime = tokenExpirationTime;
	}

	public String getTokenIssuer() {
		return tokenIssuer;
	}

	public void setTokenIssuer(String tokenIssuer) {
		this.tokenIssuer = tokenIssuer;
	}

	public String getTokenSigningKey() {
		return tokenSigningKey;
	}

	public void setTokenSigningKey(String tokenSigningKey) {
		this.tokenSigningKey = tokenSigningKey;
	}

	public Integer getRefreshTokenExpTime() {
		return refreshTokenExpTime;
	}

	public void setRefreshTokenExpTime(Integer refreshTokenExpTime) {
		this.refreshTokenExpTime = refreshTokenExpTime;
	}

	public Long getAccess_token_expiration() {
		return access_token_expiration;
	}

	public void setAccess_token_expiration(Long access_token_expiration) {
		this.access_token_expiration = access_token_expiration;
	}

	public Long getRefresh_token_expiration() {
		return refresh_token_expiration;
	}

	public void setRefresh_token_expiration(Long refresh_token_expiration) {
		this.refresh_token_expiration = refresh_token_expiration;
	}

}
