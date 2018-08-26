/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot.jwt;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepository;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtPrincipalRepository implements ShiroPrincipalRepository<JwtPlayload> {

	@Override
	public DelegateAuthenticationInfo getAuthenticationInfo(DelegateAuthenticationToken token)
			throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principal
	 * @return
	 */
	@Override
	public Set<String> getRoles(JwtPlayload principal) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principals
	 * @return
	 */
	@Override
	public Set<String> getRoles(Set<JwtPlayload> principals) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principal
	 * @return
	 */
	@Override
	public Set<String> getPermissions(JwtPlayload principal) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principals
	 * @return
	 */

	@Override
	public Set<String> getPermissions(Set<JwtPlayload> principals) {
		// TODO Auto-generated method stub
		return null;
	}

}
