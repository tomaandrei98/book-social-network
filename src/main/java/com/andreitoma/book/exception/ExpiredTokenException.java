package com.andreitoma.book.exception;

public class ExpiredTokenException extends BaseException {
    public ExpiredTokenException(String message) {
        super(message);
    }

    public ExpiredTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public ExpiredTokenException(Throwable cause) {
        super(cause);
    }

    public ExpiredTokenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
