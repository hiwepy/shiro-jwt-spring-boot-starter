package org.apache.shiro.spring.boot.jwt.verifier;

import java.util.Date;

import org.apache.shiro.spring.boot.jwt.time.JwtTimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

public class ExtendedMACVerifier extends MACVerifier {

	private Logger logger = LoggerFactory.getLogger(getClass());
	private final JWTClaimsSet claimsSet;
	private final JwtTimeProvider timeProvider;
	
	public ExtendedMACVerifier(final byte[] sharedSecret, JWTClaimsSet claimsSet, JwtTimeProvider timeProvider) throws JOSEException {
		super(sharedSecret);
		this.claimsSet = claimsSet;
		this.timeProvider = timeProvider;
	}

	public ExtendedMACVerifier(final String sharedSecretString, JWTClaimsSet claimsSet, JwtTimeProvider timeProvider) throws JOSEException {
		super(sharedSecretString);
		this.claimsSet = claimsSet;
		this.timeProvider = timeProvider;
	}

	@Override
	public boolean verify(final JWSHeader header, final byte[] signingInput, final Base64URL signature)
			throws JOSEException {
		boolean value = super.verify(header, signingInput, signature);

		if (value) {

			Date issuedAt = claimsSet.getIssueTime();
			Date notBefore = claimsSet.getNotBeforeTime();
			Date expiration = claimsSet.getExpirationTime();
			long currentTimeMillis = timeProvider.now();

			if (logger.isDebugEnabled()) {
				logger.debug("JWT IssuedAt:" + issuedAt);
				logger.debug("JWT NotBefore:" + notBefore);
				logger.debug("JWT Expiration:" + expiration);
				logger.debug("JWT Now:" + new Date(currentTimeMillis));
			}

			return notBefore != null && notBefore.getTime() <= currentTimeMillis && expiration != null
					&& currentTimeMillis < expiration.getTime();
		}

		return value;
	}
}
