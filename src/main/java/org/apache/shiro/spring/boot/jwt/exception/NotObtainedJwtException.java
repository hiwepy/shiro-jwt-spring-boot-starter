package org.apache.shiro.spring.boot.jwt.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class NotObtainedJwtException extends AuthenticationException {
	
	public NotObtainedJwtException() {
		super();
	}

	public NotObtainedJwtException(String message, Throwable cause) {
		super(message, cause);
	}

	public NotObtainedJwtException(String message) {
		super(message);
	}

	public NotObtainedJwtException(Throwable cause) {
		super(cause);
	}
	
}
