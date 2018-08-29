package org.apache.shiro.spring.boot.jwt.verifier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

public class ExtendedMACVerifier extends MACVerifier {

	private final JWTClaimsSet claimsSet;

	public ExtendedMACVerifier(final byte[] sharedSecret, JWTClaimsSet claimsSet) throws JOSEException {
		super(sharedSecret);
		this.claimsSet = claimsSet;
	}

	public ExtendedMACVerifier(final String sharedSecretString, JWTClaimsSet claimsSet) throws JOSEException {
		super(sharedSecretString);
		this.claimsSet = claimsSet;
	}

	@Override
	public boolean verify(final JWSHeader header, final byte[] signingInput, final Base64URL signature)
			throws JOSEException {
		boolean value = super.verify(header, signingInput, signature);
		long time = System.currentTimeMillis();

		return value && claimsSet.getNotBeforeTime().getTime() <= time
				&& time < claimsSet.getExpirationTime().getTime();
	}
}
