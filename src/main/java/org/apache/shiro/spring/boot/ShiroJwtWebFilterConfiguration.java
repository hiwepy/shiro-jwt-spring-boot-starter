package org.apache.shiro.spring.boot;

import java.util.List;

import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.spring.boot.biz.ShiroBizFilterFactoryBean;
import org.apache.shiro.spring.boot.jwt.authc.JwtAuthenticatingFilter;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.springframework.beans.factory.annotation.Autowired;
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

	/**
	 * JSON Web Token (JWT) Authentication Filter </br>
	 * 该过滤器负责用户的认证工作
	 */
	@Bean("authc")
	@ConditionalOnMissingBean(name = "authc")
	public FilterRegistrationBean<JwtAuthenticatingFilter> authenticationFilter(
			@Autowired(required = false) List<LoginListener> loginListeners){
		
		JwtAuthenticatingFilter authenticationFilter = new JwtAuthenticatingFilter();
		//登录监听：实现该接口可监听账号登录失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		authenticationFilter.setLoginListeners(loginListeners);
		
		/* * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，
		 * 而不是Shiro中配置的一部分URL。下面方式可以解决该问题*/
		 
		FilterRegistrationBean<JwtAuthenticatingFilter> registration = new FilterRegistrationBean<JwtAuthenticatingFilter>();
		registration.setFilter(authenticationFilter);
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
