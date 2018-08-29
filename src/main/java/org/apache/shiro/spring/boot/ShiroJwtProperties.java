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

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.shiro.biz.web.filter.authc.KickoutSessionControlFilter;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.springframework.beans.factory.annotation.Value;
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
	
	private boolean cachingEnabled;

	/**
	 * The cache used by this realm to store AuthorizationInfo instances associated
	 * with individual Subject principals.
	 */
	private boolean authorizationCachingEnabled;
	private String authorizationCacheName;

	private boolean authenticationCachingEnabled;
	private String authenticationCacheName;
	 
	/** 登录地址：会话不存在时访问的地址 */
	private String loginUrl;
	/** 重定向地址：会话注销后的重定向地址 */
    private String redirectUrl;
	/** 系统主页：登录成功后跳转路径 */
    private String successUrl;
    /** 异常页面：无权限时的跳转路径 */
    private String unauthorizedUrl;
    /** jwt秘钥 */
    private String salt;
  /*  private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.RSA_OAEP_256;
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128CBC_HS256;
    */
    
    /**
     * If Check JWT Validity.
     */
    private boolean checkExpiry;
    
    /**
     * {@link JwtToken} will expire after this time.
     */
    private Integer tokenExpirationTime;

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
    
    
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access_token.expiration}")
    private Long access_token_expiration;

    @Value("${jwt.refresh_token.expiration}")
    private Long refresh_token_expiration;
    
    
    public Integer getRefreshTokenExpTime() {
        return refreshTokenExpTime;
    }

    public void setRefreshTokenExpTime(Integer refreshTokenExpTime) {
        this.refreshTokenExpTime = refreshTokenExpTime;
    }

    public Integer getTokenExpirationTime() {
        return tokenExpirationTime;
    }
    
    public void setTokenExpirationTime(Integer tokenExpirationTime) {
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
    
    
    /** 认证IP正则表达式：可实现IP访问限制 */
    private String ipRegexpPattern;
    
	private Map<String /* pattert */, String /* Chain names */> filterChainDefinitionMap = new LinkedHashMap<String, String>();
	
	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}
	
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public String getAuthorizationCacheName() {
        return authorizationCacheName;
    }

    public void setAuthorizationCacheName(String authorizationCacheName) {
        this.authorizationCacheName = authorizationCacheName;
    }

    /**
     * Returns {@code true} if authorization caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true}.
     *
     * @return {@code true} if authorization caching should be utilized, {@code false} otherwise.
     */
    public boolean isAuthorizationCachingEnabled() {
        return isCachingEnabled() && authorizationCachingEnabled;
    }

    /**
     * Sets whether or not authorization caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true}.
     *
     * @param authenticationCachingEnabled the value to set
     */
    public void setAuthorizationCachingEnabled(boolean authenticationCachingEnabled) {
        this.authorizationCachingEnabled = authenticationCachingEnabled;
        if (authenticationCachingEnabled) {
            setCachingEnabled(true);
        }
    }
	    
	/**
     * Returns the name of a {@link Cache} to lookup from any available {@link #getCacheManager() cacheManager} if
     * a cache is not explicitly configured via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * <p/>
     * This name will only be used to look up a cache if authentication caching is
     * {@link #isAuthenticationCachingEnabled() enabled}.
     * <p/>
     * <b>WARNING:</b> Only set this property if safe caching conditions apply, as documented at the top
     * of this page in the class-level JavaDoc.
     *
     * @return the name of a {@link Cache} to lookup from any available {@link #getCacheManager() cacheManager} if
     *         a cache is not explicitly configured via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * @see #isAuthenticationCachingEnabled()
     * @since 1.2
     */
    public String getAuthenticationCacheName() {
        return this.authenticationCacheName;
    }

    /**
     * Sets the name of a {@link Cache} to lookup from any available {@link #getCacheManager() cacheManager} if
     * a cache is not explicitly configured via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * <p/>
     * This name will only be used to look up a cache if authentication caching is
     * {@link #isAuthenticationCachingEnabled() enabled}.
     *
     * @param authenticationCacheName the name of a {@link Cache} to lookup from any available
     *                                {@link #getCacheManager() cacheManager} if a cache is not explicitly configured
     *                                via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * @see #isAuthenticationCachingEnabled()
     * @since 1.2
     */
    public void setAuthenticationCacheName(String authenticationCacheName) {
        this.authenticationCacheName = authenticationCacheName;
    }

    /**
     * Returns {@code true} if authentication caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true}.
     *
     * @return {@code true} if authentication caching should be utilized, {@code false} otherwise.
     */
    public boolean isAuthenticationCachingEnabled() {
        return this.authenticationCachingEnabled && isCachingEnabled();
    }

    /**
     * Sets whether or not authentication caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code false} to retain backwards compatibility with Shiro 1.1 and earlier.
     * <p/>
     * <b>WARNING:</b> Only set this property to {@code true} if safe caching conditions apply, as documented at the top
     * of this page in the class-level JavaDoc.
     *
     * @param authenticationCachingEnabled the value to set
     */
    public void setAuthenticationCachingEnabled(boolean authenticationCachingEnabled) {
        this.authenticationCachingEnabled = authenticationCachingEnabled;
        if (authenticationCachingEnabled) {
            setCachingEnabled(true);
        }
    }
    
	/**
     * Returns {@code true} if caching should be used if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true} since the large majority of Realms will benefit from caching if a CacheManager
     * has been configured.  However, memory-only realms should set this value to {@code false} since they would
     * manage account data in memory already lookups would already be as efficient as possible.
     *
     * @return {@code true} if caching will be globally enabled if a {@link CacheManager} has been
     *         configured, {@code false} otherwise
     */
    public boolean isCachingEnabled() {
        return cachingEnabled;
    }

    /**
     * Sets whether or not caching should be used if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}.
     *
     * @param cachingEnabled whether or not to globally enable caching for this realm.
     */
    public void setCachingEnabled(boolean cachingEnabled) {
        this.cachingEnabled = cachingEnabled;
    }

	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	public String getSuccessUrl() {
		return successUrl;
	}

	public void setSuccessUrl(String successUrl) {
		this.successUrl = successUrl;
	}

	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}

	public void setUnauthorizedUrl(String unauthorizedUrl) {
		this.unauthorizedUrl = unauthorizedUrl;
	}

	public Map<String, String> getFilterChainDefinitionMap() {
		return filterChainDefinitionMap;
	}

	public void setFilterChainDefinitionMap(Map<String, String> filterChainDefinitionMap) {
		this.filterChainDefinitionMap = filterChainDefinitionMap;
	}

	/*public JWSAlgorithm getJwsAlgorithm() {
		return jwsAlgorithm;
	}

	public void setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
		this.jwsAlgorithm = jwsAlgorithm;
	}

	public JWEAlgorithm getJweAlgorithm() {
		return jweAlgorithm;
	}

	public void setJweAlgorithm(JWEAlgorithm jweAlgorithm) {
		this.jweAlgorithm = jweAlgorithm;
	}

	public EncryptionMethod getEncryptionMethod() {
		return encryptionMethod;
	}

	public void setEncryptionMethod(EncryptionMethod encryptionMethod) {
		this.encryptionMethod = encryptionMethod;
	}*/

}

