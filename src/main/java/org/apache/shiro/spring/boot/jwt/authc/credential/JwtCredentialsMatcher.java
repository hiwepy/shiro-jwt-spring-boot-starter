/*
 * Copyright 2017-2018 the original author(https://github.com/wj596)
 * 
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </p>
 */
package org.apache.shiro.spring.boot.jwt.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 * JSON Web Token (JWT) Credentials Matcher
 */
public class JwtCredentialsMatcher implements CredentialsMatcher {
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		String jwt = (String) info.getCredentials();
		/*
		
		StatelessLogined statelessAccount = null;
		try{
			if(Commons.hasLen(this.properties.getJwtSecretKey())){
				statelessAccount = this.cryptoService.parseJwt(jwt);
			} else {
				String appId = (String) Commons.readValue(Commons.parseJwtPayload(jwt)).get("subject");
				String appKey = accountProvider.loadAppKey(appId);
				if(Strings.isNullOrEmpty(appKey)) 
					throw new AuthenticationException(MessageConfig.MSG_NO_SECRET_KEY);
				statelessAccount = this.cryptoService.parseJwt(jwt,appKey);
			}
			
		} catch(SignatureException e){
			throw new AuthenticationException(this.properties.getJwtSecretKey());
		} catch(ExpiredJwtException e){
			throw new AuthenticationException(this.messages.getMsgJwtTimeout());
		} catch(Exception e){
			throw new AuthenticationException(this.messages.getMsgJwtError());
		}
		if(null == statelessAccount){
			throw new AuthenticationException(this.messages.getMsgJwtError());
		}
		String tokenId = statelessAccount.getTokenId();
		if(this.properties.isJwtBurnEnabled()
				&&this.cacheDelegator.cutBurnedToken(tokenId)){
			throw new AuthenticationException(MessageConfig.MSG_BURNED_TOKEN);
		}*/
        return true;
	}

}