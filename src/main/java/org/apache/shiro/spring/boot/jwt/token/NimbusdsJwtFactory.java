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
package org.apache.shiro.spring.boot.jwt.token;

import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * TODO
 * 
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */

public class NimbusdsJwtFactory implements JwtFactory {

	/**
	 * TODO
	 * 
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param id
	 * @param subject
	 * @param issuer
	 * @param period
	 * @param roles
	 * @param permissions
	 * @param algorithm
	 * @return
	 * @throws Exception 
	 */
	@Override
	public String issueJwt(String signingKey, String id, String subject, String issuer, Long period, String roles,
			String permissions, String algorithm) throws Exception {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		builder.jwtID(id);
		builder.issuer(issuer);
		builder.subject(subject);
		builder.issueTime(new Date());
		builder.notBeforeTime(new Date());
		builder.expirationTime(new Date(new Date().getTime() + period));

		JWTClaimsSet claimsSet = builder.build();
		JWSHeader header = new JWSHeader(JWSAlgorithm.parse(algorithm));

		Payload payload = new Payload(claimsSet.toJSONObject());

		JWSObject jwsObject = new JWSObject(header, payload);

		JWSSigner signer = new MACSigner(signingKey);
		jwsObject.sign(signer);
		return jwsObject.serialize();
	}

}
