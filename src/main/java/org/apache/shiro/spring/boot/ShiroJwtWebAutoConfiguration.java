package org.apache.shiro.spring.boot;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.biz.realm.PrincipalRealmListener;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.jwt.JwtPrincipalRepository;
import org.apache.shiro.spring.boot.jwt.realm.JwtExternalAuthorizingRealm;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ObjectUtils;


@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnProperty(prefix = ShiroJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroBizProperties.class, ShiroJwtProperties.class })
public class ShiroJwtWebAutoConfiguration extends AbstractShiroWebConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;
	
	@Autowired
	private ShiroBizProperties properties;
	
	/**
	 * Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("realmListeners")
	@ConditionalOnMissingBean(name = "realmListeners")
	public List<PrincipalRealmListener> realmListeners() {

		List<PrincipalRealmListener> realmListeners = new ArrayList<PrincipalRealmListener>();
		
		Map<String, PrincipalRealmListener> beansOfType = getApplicationContext().getBeansOfType(PrincipalRealmListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, PrincipalRealmListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				realmListeners.add(ite.next().getValue());
			}
		}
		
		return realmListeners;
	}
	
	@Bean
	public Realm jwtRealm(@Qualifier("jwtRepository") JwtPrincipalRepository repository,
			List<PrincipalRealmListener> realmsListeners) {
		
		JwtExternalAuthorizingRealm jwtRealm = new JwtExternalAuthorizingRealm();
		//认证账号信息提供实现：认证信息、角色信息、权限信息；业务系统需要自己实现该接口
		jwtRealm.setRepository(repository);
		//凭证匹配器：该对象主要做密码校验
		jwtRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		//Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		jwtRealm.setRealmsListeners(realmsListeners);
		//缓存相关的配置：采用提供的默认配置即可
		jwtRealm.setCachingEnabled(properties.isCachingEnabled());
		//认证缓存配置
		jwtRealm.setAuthenticationCachingEnabled(properties.isAuthenticationCachingEnabled());
		jwtRealm.setAuthenticationCacheName(properties.getAuthenticationCacheName());
		//授权缓存配置
		jwtRealm.setAuthorizationCachingEnabled(properties.isAuthorizationCachingEnabled());
		jwtRealm.setAuthorizationCacheName(properties.getAuthorizationCacheName());
		
		//设置jwt认证地址和应用服务地址
		/*jwtRealm.setCasServerUrlPrefix(properties.getCasServerUrlPrefix());
		if(StringUtils.hasText(properties.getServerName())) {	
			jwtRealm.setCasService(properties.getServerName());
		} else {
			jwtRealm.setCasService(properties.getService());
		}*/
		
		return jwtRealm;
	}
	
	/**
	 * 责任链定义 ：定义Shiro的逻辑处理责任链
	 */
	@Bean
    @ConditionalOnMissingBean
    @Override
	protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
		DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
		Map<String /* pattert */, String /* Chain names */> pathDefinitions = properties.getFilterChainDefinitionMap();
		if (MapUtils.isNotEmpty(pathDefinitions)) {
			chainDefinition.addPathDefinitions(pathDefinitions);
			return chainDefinition;
		}
		chainDefinition.addPathDefinition("/logout", "logout");
		chainDefinition.addPathDefinition("/**", "authc");
		return chainDefinition;
	}
	 
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
	
}
