package org.apache.shiro.spring.boot;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.shiro.spring.boot.jwt.ShiroJwtFilterFactoryBean;
import org.apache.shiro.spring.boot.jwt.filter.JWTOrFormAuthenticationFilter;
import org.apache.shiro.spring.boot.jwt.filter.JwtLogoutFilter;
import org.apache.shiro.spring.boot.jwt.filter.JwtTokenValidationFilter;
import org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;


@Configuration
@ConditionalOnWebApplication
@AutoConfigureBefore(ShiroWebAutoConfiguration.class)
@ConditionalOnClass()
@ConditionalOnProperty(prefix = ShiroJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroProperties.class, ShiroJwtProperties.class })
public class ShiroJwtWebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private static final Logger LOG = LoggerFactory.getLogger(ShiroJwtWebFilterConfiguration.class);
	private ApplicationContext applicationContext;
	
	@Autowired
	private ShiroProperties properties;
	@Autowired
	private ShiroJwtProperties casProperties;
	@Autowired
	private ServerProperties serverProperties;

	/**
	 * Jwt Authentication Filter </br>
	 * 该过滤器负责用户的认证工作
	 */
	@Bean("authc")
	@ConditionalOnMissingBean(name = "authc")
	public FilterRegistrationBean authenticationFilter(ShiroJwtProperties properties){
		FilterRegistrationBean registration = new FilterRegistrationBean(); 
		JWTOrFormAuthenticationFilter authenticationFilter = new JWTOrFormAuthenticationFilter();
		//authenticationFilter.setFailureUrl(properties.getFailureUrl());
		registration.setFilter(authenticationFilter);
	    registration.setEnabled(false); 
	    return registration;
	}

	/**
	 * Jwt Token Validation Filter </br>
	 * 该过滤器负责对Token的校验工作
	 */
	@Bean("tokenValid")
	@ConditionalOnMissingBean(name = "tokenValid")
	public FilterRegistrationBean tokenValidationFilter(ShiroJwtProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new JwtTokenValidationFilter());
		filterRegistration.setEnabled(false); 
		 
		// JwtTokenValidationFilter
		/*filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(properties.isEncodeServiceUrl()));
		if(StringUtils.hasText(properties.getEncoding())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ENCODING.getName(), properties.getEncoding());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.EXCEPTION_ON_VALIDATION_FAILURE.getName(), Boolean.toString(properties.isExceptionOnValidationFailure()));
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), properties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), properties.getCasServerUrlPrefix());
		if(StringUtils.hasText(properties.getHostnameVerifier())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER.getName(), properties.getHostnameVerifier());
		}
		if(StringUtils.hasText(properties.getHostnameVerifierConfig())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER_CONFIG.getName(), properties.getHostnameVerifierConfig());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.REDIRECT_AFTER_VALIDATION.getName(), Boolean.toString(properties.isRedirectAfterValidation()));
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(properties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), properties.getServerName());
		} else if(StringUtils.hasText(properties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), properties.getService());
		}
		if(StringUtils.hasText(properties.getSslConfigFile())) {
			filterRegistration.addInitParameter(ConfigurationKeys.SSL_CONFIG_FILE.getName(), properties.getSslConfigFile());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.USE_SESSION.getName(), Boolean.toString(properties.isUseSession()));
		*/
		
	    return filterRegistration;
	}

	/**
	 * Jwt Logout Filter </br>
	 */
	@Bean("logout")
	@ConditionalOnMissingBean(name = "logout")
	public FilterRegistrationBean logoutFilter(ShiroJwtProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new JwtLogoutFilter());
		filterRegistration.setEnabled(false);
		return filterRegistration;
	}
	
	@Bean
    @ConditionalOnMissingBean
    @Override
    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
		
		ShiroFilterFactoryBean filterFactoryBean = new ShiroJwtFilterFactoryBean();
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
    protected FilterRegistrationBean filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(Integer.MAX_VALUE);

        return filterRegistrationBean;
    }
    
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
	
}
