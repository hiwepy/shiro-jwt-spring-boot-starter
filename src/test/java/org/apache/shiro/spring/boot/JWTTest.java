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
package org.apache.shiro.spring.boot;

import java.util.Map;
import java.util.Random;

import org.junit.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * TODO
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class JWTTest {

	@Test 
	public String applyToken(){ 
		Long current = System.currentTimeMillis() ; 
		String url = "http://localhost:8080/tokenServer/auth/apply-token"; 
		MultiValueMap<String, Object> dataMap = new LinkedMultiValueMap<String, Object>(); 
		String clientKey = "administrator";
		// 客户端标识（用户名）
		String mix = String.valueOf(new Random().nextFloat());
		// 随机数，进行混淆 
		String timeStamp = current.toString();
		// 时间戳 
		dataMap.add("clientKey", clientKey); 
		dataMap.add("mix", mix); 
		dataMap.add("timeStamp", timeStamp);
		String baseString = clientKey+mix+timeStamp; 
		String digest = hmacDigest(baseString);
		// 生成HMAC摘要 
		dataMap.add("digest", digest); 
		Map result = rt.postForObject(url, dataMap, Map.class); 
		return (String)result.get("jwt"); 
	}
	
	
}
