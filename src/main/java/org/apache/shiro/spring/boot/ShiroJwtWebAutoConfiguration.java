package org.apache.shiro.spring.boot;

import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.spring.boot.jwt.authc.JwtSubjectFactory;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//https://blog.csdn.net/weixin_42058600/article/details/81837056
@Configuration
@AutoConfigureBefore(name = { "org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnProperty(prefix = ShiroJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroBizProperties.class, ShiroJwtProperties.class })
public class ShiroJwtWebAutoConfiguration extends AbstractShiroWebConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private ShiroBizProperties bizProperties;

	@Bean
	@Override
	protected SubjectFactory subjectFactory() {
		return new JwtSubjectFactory(bizProperties.isSessionStateless());
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
