package org.apache.shiro.spring.boot.jwt;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import org.apache.shiro.biz.principal.Principal;
import org.apache.shiro.biz.principal.PrincipalRepository;
import org.apache.shiro.spring.boot.jwt.verifier.MACVerifierExtended;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public abstract class JwtPrincipalRepository implements PrincipalRepository {

	public byte[] generateSharedKey() {
        SecureRandom random = new SecureRandom();
        byte[] sharedKey = new byte[32];
        random.nextBytes(sharedKey);
        return sharedKey;
    }

	public long getExpirationDate() {
        return 1000 * 60 * 60 * 24 * 5;
    }

    public abstract String getIssuer();

    public abstract byte[] getSharedKey();

    public TokenResponse createToken(Principal user) {
        TokenResponse response = new TokenResponse(user, createToken(user.getUserkey()));
        return response;
    }

    public String createToken(String userId) {
        try {
        	
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

            builder.issuer(getIssuer());
            builder.subject(userId.toString());
            builder.issueTime(new Date());
            builder.notBeforeTime(new Date());
            builder.expirationTime(new Date(new Date().getTime() + getExpirationDate()));
            builder.jwtID(UUID.randomUUID().toString());

            JWTClaimsSet claimsSet = builder.build();
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

            Payload payload = new Payload(claimsSet.toJSONObject());

            JWSObject jwsObject = new JWSObject(header, payload);

            JWSSigner signer = new MACSigner(getSharedKey());
            jwsObject.sign(signer);
            return jwsObject.serialize();
        } catch (JOSEException ex) {
            return null;
        }
    }

    public boolean validateToken(String token) {

        try {
            SignedJWT signed = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifierExtended(getSharedKey(), signed.getJWTClaimsSet());
            return signed.verify(verifier);
        } catch (ParseException ex) {
            return false;
        } catch (JOSEException ex) {
            return false;
        }

    }
	
}
