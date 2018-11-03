# spring-boot-starter-shiro-jwt
shiro jwt starter for spring boot

### 说明


 > 基于 Shiro + Jwt 的 Spring Boot Starter 实现


### Maven

``` xml
<dependency>
	<groupId>${project.groupId}</groupId>
	<artifactId>spring-boot-starter-shiro-jwt</artifactId>
	<version>1.0.2.RELEASE</version>
</dependency>
```

### Sample

[https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-shiro-biz](https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-shiro-biz "spring-boot-sample-shiro-biz")

### 配置参考

 > application.yml

################################################################################################################  
###Shiro 权限控制基本配置：  
################################################################################################################
shiro:
  annotations: 
    enabled: true
    proxy-target-class: true
  authentication-caching-enabled: false
  authentication-cache-name: SHIRO-AUTHC
  authorization-caching-enabled: false 
  authorization-cache-name: SHIRO-AUTHZ
  caching-enabled: false
  cache:
    type: ehcache
  enabled: true
  kaptcha:
    enabled: true
    retry-times-when-access-denied: 3
  failure-url: /error
  http:
    header:
      access-control-allow-methods: PUT,POST,GET,DELETE,OPTIONS
  jwt:
    enabled: true
  login-url: /authz/login/slogin
  redirect-url: /authz/login/index
  success-url: /index
  session-creation-enabled: false
  session-validation-scheduler-enabled: false
  session-validation-interval: 20000
  session-stateless: true
  session-storage-enabled: false
  session-timeout: 1800000
  unauthorized-url: /error
  user-native-session-manager: false
  web: 
    enabled: true
  filter-chain-definition-map: 
    '[/]' : anon
    '[/**/favicon.ico]' : anon
    '[/webjars/**]' : anon
    '[/assets/**]' : anon
    '[/error*]' : anon
    '[/logo/**]' : anon
    '[/swagger-ui.html**]' : anon
    '[/swagger-resources/**]' : anon
    '[/v2/**]' : anon
    '[/kaptcha*]' : anon
    '[/admin]' : anon
    '[/admin/assets/**]' : anon
    '[/admin/applications]' : anon
    '[/admin/applications/**]' : anon
    '[/admin/notifications]' : anon
    '[/admin/notifications/**]' : anon
    '[/admin/instances]' : anon
    '[/admin/instances/**]' : anon
    '[/sockets/**]' : anon
    '[/expiry]' : cros,withinExpiry
    '[/authz/login/slogin]' : cros,authc
    '[/logout]' : logout
    '[/**]' : cros,authc


### 参考资料

http://shiro.apache.org/documentation.html

http://jinnianshilongnian.iteye.com/blog/2018398

