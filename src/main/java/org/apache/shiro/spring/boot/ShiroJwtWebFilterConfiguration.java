package org.apache.shiro.spring.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.biz.authc.AuthenticationFailureHandler;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.biz.web.filter.authc.AuthenticatingFailureRequestCounter;
import org.apache.shiro.biz.web.filter.authc.captcha.CaptchaResolver;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.biz.ShiroBizFilterFactoryBean;
import org.apache.shiro.spring.boot.captcha.ShiroKaptchaProperties;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.boot.jwt.JwtPrincipalRepository;
import org.apache.shiro.spring.boot.jwt.authc.JwtAuthenticatingFilter;
import org.apache.shiro.spring.boot.jwt.authz.JwtWithinExpiryFilter;
import org.apache.shiro.spring.boot.jwt.realm.JwtStatelessAuthorizingRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnProperty(prefix = ShiroJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroBizProperties.class, ShiroJwtProperties.class })
public class ShiroJwtWebFilterConfiguration extends AbstractShiroWebFilterConfiguration {
	
	@Autowired
	private ShiroBizProperties properties;
	
	@Bean("jwtRepository")
	public JwtPrincipalRepository jwtRepository(
			JwtPayloadRepository jwtPayloadRepository,
			ShiroJwtProperties properties) {
		JwtPrincipalRepository jwtRepository = new JwtPrincipalRepository(jwtPayloadRepository);
		jwtRepository.setCheckExpiry(properties.isCheckExpiry());
		return jwtRepository;
	}

	@Bean
	public Realm jwtRealm(@Qualifier("jwtRepository") JwtPrincipalRepository jwtRepository,
			List<AuthorizingRealmListener> realmsListeners, 
			ShiroBizProperties properties) {

		JwtStatelessAuthorizingRealm jwtRealm = new JwtStatelessAuthorizingRealm() {
			
			@Override
			protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
					throws AuthenticationException {
				// 认证协议：CAS、HTTP、JWT、KISSO、LDAP、OAuth2、OpenID、SMAL等
				ThreadContext.put("protocol", "JWT");
				// 负责此次认证的realm名称
				ThreadContext.put("realm", "JwtStatelessAuthorizingRealm");
				return super.doGetAuthenticationInfo(token);
			}

			@Override
			protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
				// 认证协议：CAS、HTTP、JWT、KISSO、LDAP、OAuth2、OpenID、SMAL等
				ThreadContext.put("protocol", "JWT");
				// 负责此次认证的realm名称
				ThreadContext.put("realm", "JwtStatelessAuthorizingRealm");
				return super.doGetAuthorizationInfo(principals);
			}

		};
		// 认证账号信息提供实现：认证信息、角色信息、权限信息；业务系统需要自己实现该接口
		jwtRealm.setRepository(jwtRepository);
		// 凭证匹配器：该对象主要做密码校验
		jwtRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		// Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		jwtRealm.setRealmsListeners(realmsListeners);
		// 缓存相关的配置：采用提供的默认配置即可
		jwtRealm.setCachingEnabled(properties.isCachingEnabled());
		// 认证缓存配置:无状态情况不缓存认证信息
		jwtRealm.setAuthenticationCachingEnabled(properties.isAuthenticationCachingEnabled());
		jwtRealm.setAuthenticationCacheName(properties.getAuthenticationCacheName());
		// 授权缓存配置:无状态情况不缓存认证信息
		jwtRealm.setAuthorizationCachingEnabled(properties.isAuthorizationCachingEnabled());
		jwtRealm.setAuthorizationCacheName(properties.getAuthorizationCacheName());

		// 设置jwt认证地址和应用服务地址
		/*
		 * jwtRealm.setCasServerUrlPrefix(properties.getCasServerUrlPrefix());
		 * if(StringUtils.hasText(properties.getServerName())) {
		 * jwtRealm.setCasService(properties.getServerName()); } else {
		 * jwtRealm.setCasService(properties.getService()); }
		 */

		return jwtRealm;
	}
	
	/**
	 * 默认的登录验证过滤器
	 */
	@Bean("jwt")
	public FilterRegistrationBean<JwtAuthenticatingFilter> authenticationFilter(
			JwtPayloadRepository jwtPayloadRepository,
			ObjectProvider<LoginListener> loginListenerProvider,
			@Autowired(required = false) List<AuthenticationSuccessHandler> successHandlers,
			@Autowired(required = false) List<AuthenticationFailureHandler> failureHandlers,
			CaptchaResolver captchaResolver, 
			ShiroBizProperties properties, 
			ShiroKaptchaProperties kaptchaProperties,
			ShiroJwtProperties jwtProperties) {

		JwtAuthenticatingFilter authcFilter = new JwtAuthenticatingFilter() {
			/*
			 * 二期 protected String getUsername(ServletRequest request) { return
			 * WebUtils.getCleanParam(request, getUsernameParam()); }
			 * 
			 * protected String getPassword(ServletRequest request) { return
			 * WebUtils.getCleanParam(request, getPasswordParam()); }
			 */
		};

		// JSON Web Token (JWT) 提供者
		authcFilter.setJwtPayloadRepository(jwtPayloadRepository);
		// 登陆失败重试次数，超出限制需要输入验证码
		authcFilter.setRetryTimesWhenAccessDenied(kaptchaProperties.getRetryTimesWhenAccessDenied());
		// 是否验证验证码
		authcFilter.setCaptchaEnabled(properties.isEnabled());
		// 验证码解析器
		authcFilter.setCaptchaResolver(captchaResolver);

		// 监听器
		authcFilter.setLoginListeners(loginListenerProvider.stream().collect(Collectors.toList()));
		authcFilter.setFailureHandlers(failureHandlers);
		authcFilter.setSuccessHandlers(successHandlers);

		authcFilter.setFailureCounter(new AuthenticatingFailureRequestCounter());
		// authcFilter.setFailureCounter(new AuthenticatingFailureSessionCounter());
		authcFilter.setSessionStateless(properties.isSessionStateless());
		authcFilter.setCheckExpiry(jwtProperties.isCheckExpiry());

		/*
		 * * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter
		 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤， 而不是Shiro中配置的一部分URL。下面方式可以解决该问题
		 */

		FilterRegistrationBean<JwtAuthenticatingFilter> registration = new FilterRegistrationBean<JwtAuthenticatingFilter>(
				authcFilter);
		registration.setEnabled(false);
		return registration;
	}

	/**
	 * JSON Web Token (JWT) Expiry Validation Filter </br>
	 * 该过滤器负责JWT有效期检查的工作
	 */
	@Bean("withinExpiry")
	public FilterRegistrationBean<JwtWithinExpiryFilter> withinExpiryFilter(
			JwtPayloadRepository jwtPayloadRepository, 
			ShiroBizProperties properties,
			ShiroJwtProperties jwtProperties) {

		JwtWithinExpiryFilter authzFilter = new JwtWithinExpiryFilter();

		// JSON Web Token (JWT) 提供者
		authzFilter.setJwtPayloadRepository(jwtPayloadRepository);

		authzFilter.setCheckExpiry(jwtProperties.isCheckExpiry());

		/*
		 * * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter
		 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤， 而不是Shiro中配置的一部分URL。下面方式可以解决该问题
		 */

		FilterRegistrationBean<JwtWithinExpiryFilter> registration = new FilterRegistrationBean<JwtWithinExpiryFilter>();
		registration.setFilter(authzFilter);
		registration.setEnabled(false);
		return registration;
	}
	
	@Bean
    @ConditionalOnMissingBean
    @Override
    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
		
		ShiroFilterFactoryBean filterFactoryBean = new ShiroBizFilterFactoryBean();
		//系统主页：登录成功后跳转路径
        filterFactoryBean.setSuccessUrl(properties.getSuccessUrl());
        //异常页面：无权限时的跳转路径
        filterFactoryBean.setUnauthorizedUrl(properties.getUnauthorizedUrl());
        
        //必须设置 SecurityManager
   		filterFactoryBean.setSecurityManager(securityManager);
   		//拦截规则
        filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        
        return filterFactoryBean;
        
    }

    @Bean(name = "filterShiroFilterRegistrationBean")
    @ConditionalOnMissingBean
    protected FilterRegistrationBean<AbstractShiroFilter> filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean<AbstractShiroFilter> filterRegistrationBean = new FilterRegistrationBean<AbstractShiroFilter>();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(Integer.MAX_VALUE);

        return filterRegistrationBean;
    }
    
}
