package org.apache.shiro.spring.boot.jwt.realm;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.ExternalAuthorizingRealm;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.ShiroJwtProperties;
import org.apache.shiro.spring.boot.jwt.JwtPlayload;
import org.apache.shiro.spring.boot.jwt.token.JwtRepository;
import org.apache.shiro.spring.boot.jwt.token.JwtToken;
import org.apache.shiro.subject.PrincipalCollection;

import com.google.common.collect.Sets;

/**
 * 基于JWT（ JSON WEB TOKEN）的认证域
 * 
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class JwtExternalAuthorizingRealm<S> extends ExternalAuthorizingRealm {

	private ShiroJwtProperties jwtProperties;
	
	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;// 此Realm只支持JwtToken
	}

	/** 认证 */
	@Override
	protected AuthenticationInfo doGetExternalAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		JwtToken jwtToken = (JwtToken) token;
		
		String jwt = (String) jwtToken.getPrincipal();
		
		JwtPlayload playload = getJwtRepository().getPlayload(jwtProperties.getTokenSigningKey(), jwt);
		
		// 如果要使token只能使用一次，此处可以过滤并缓存jwtPlayload.getId()
		// 可以做签发方验证
		// 可以做接收方验证
		return new SimpleAuthenticationInfo(playload, jwt, getName());
	}

	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		JwtPlayload jwtPlayload = (JwtPlayload) principals.getPrimaryPrincipal();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		Set<String> roles = Sets.newHashSet(StringUtils.tokenizeToStringArray(jwtPlayload.getRoles()));
		info.setRoles(roles);
		// 解析权限并设置
		Set<String> permissions = Sets.newHashSet(StringUtils.tokenizeToStringArray(jwtPlayload.getPerms()));
		info.setStringPermissions(permissions);
		return info;
	}

	public ShiroJwtProperties getJwtProperties() {
		return jwtProperties;
	}

	public void setJwtProperties(ShiroJwtProperties jwtProperties) {
		this.jwtProperties = jwtProperties;
	}
	
}
