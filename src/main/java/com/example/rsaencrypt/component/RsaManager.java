package com.example.rsaencrypt.component;

import com.example.rsaencrypt.exception.EncryptException;
import com.example.rsaencrypt.utils.RsaUtil;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

/**
 * RSA 관리 객체
 */
@Component
@Scope(proxyMode = ScopedProxyMode.TARGET_CLASS, value = WebApplicationContext.SCOPE_SESSION)
public class RsaManager implements Serializable {

    @Serial
    private static final long serialVersionUID = 5863245767897538054L;

    /* RSA 개인 키 */
    private PrivateKey privateKey;

    public void setKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * RSA 복호화, 예외 발생 시 빈 문자열 반환
     *
     * @param encryptText 암호화 텍스트
     * @return 복호화 텍스트
     */
    public String decryptReturnEmptyIfException(String encryptText) {
        try {
            final byte[] decrypt = RsaUtil.decrypt(this.privateKey, encryptText);
            return new String(decrypt, StandardCharsets.UTF_8);
        } catch (EncryptException e) {
            return null;
        }
    }

}
