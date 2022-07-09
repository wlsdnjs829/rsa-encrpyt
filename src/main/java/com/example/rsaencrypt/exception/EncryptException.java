package com.example.rsaencrypt.exception;

/**
 * 암복호화 익셉션
 *
 * @author : ljw0829
 * @date : 2021-07-12 15:00
 */
public class EncryptException extends RuntimeException {
    private final String message;

    public EncryptException(String message) {
        super(message);
        this.message = message;
    }

    public EncryptException(String message, Exception e) {
        super(message, e);
        this.message = message;
    }

    /* (non-Javadoc)
     * @see java.lang.Throwable#getMessage()
     * 메시지 처리
     */
    @Override
    public String getMessage() {
        return this.message;
    }

}
