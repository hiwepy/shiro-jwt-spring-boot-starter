# shiro-jwt-spring-boot-starter
shiro jwt starter for spring boot
  
### 组件简介

> 基于 Shiro + Jwt 的 Spring Boot Starter 实现

http://shiro.apache.org/documentation.html
http://jinnianshilongnian.iteye.com/blog/2018398

### 使用说明

##### 1、Spring Boot 项目添加 Maven 依赖

``` xml
<dependency>
	<groupId>com.github.hiwepy</groupId>
	<artifactId>shiro-jwt-spring-boot-starter</artifactId>
	<version>2.0.0.RELEASE</version>
</dependency>
```

##### 2、在`application.yml`文件中增加如下配置

```yaml
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
```

##### 3、使用示例

```
 ShiroPrincipal principal = SubjectUtils.getPrincipal(ShiroPrincipal.class);
```

## Jeebiz 技术社区

Jeebiz 技术社区 **微信公共号**、**小程序**，欢迎关注反馈意见和一起交流，关注公众号回复「Jeebiz」拉你入群。

|公共号|小程序|
|---|---|
| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/qrcode_for_gh_1d965ea2dfd1_344.jpg)| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/gh_09d7d00da63e_344.jpg)|


