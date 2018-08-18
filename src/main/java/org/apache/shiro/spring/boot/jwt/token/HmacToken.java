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
/**
 * 
 */
package org.apache.shiro.spring.boot.jwt.token;

import java.util.Map;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * HMAC令牌
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 */
@SuppressWarnings("serial")
public class HmacToken implements AuthenticationToken {
	
	private String clientKey;// 客户标识（可以是用户名、app id等等）
	private String digest;// 消息摘要
	private String timeStamp;// 时间戳
	private Map<String, String[]> parameters;// 访问参数
	private String host;// 客户端IP

	public HmacToken(String clientKey, String timeStamp, String digest, String host, Map<String, String[]> parameters) {
		this.clientKey = clientKey;
		this.timeStamp = timeStamp;
		this.digest = digest;
		this.host = host;
		this.parameters = parameters;
	}

	@Override
	public Object getPrincipal() {
		return this.clientKey;
	}

	@Override
	public Object getCredentials() {
		return Boolean.TRUE;
	}

	public String getClientKey() {
		return clientKey;
	}

	public void setClientKey(String clientKey) {
		this.clientKey = clientKey;
	}

	public String getDigest() {
		return digest;
	}

	public void setDigest(String digest) {
		this.digest = digest;
	}

	public String getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}

	public Map<String, String[]> getParameters() {
		return parameters;
	}

	public void setParameters(Map<String, String[]> parameters) {
		this.parameters = parameters;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}
	
}
