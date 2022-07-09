package com.example.rsaencrypt.utils;

import com.example.rsaencrypt.exception.EncryptException;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

/**
 * RSA 암 복호화 유틸
 */
@Slf4j
@UtilityClass
public class RsaUtil {

    private static final String RSA_CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String RSA = "RSA";

    private static final int KEY_SIZE = 1024;
    private static final int RADIX = 16;
    private static final int TWO = 2;
    private static final int ZERO = 0;

    private static final String ERROR_RSA_GENERATOR_INSTANCE = "RSA Generator 생성 오류";
    private static final String ERROR_RSA_PUBLIC_KEY_SPEC = "RSA 공개 키 정보 생성 오류";
    private static final String ERROR_RSA_ENCRYPT_DECRYPT = "RSA 암 복호화 오류";

    /**
     * RSA 키 페어 조회
     */
    public KeyPair getRsaKeyPair() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(KEY_SIZE);
            return keyGen.genKeyPair();
        } catch (Exception e) {
            throw new EncryptException(ERROR_RSA_GENERATOR_INSTANCE);
        }
    }

    /**
     * RSA 공개 키 정보 조회
     *
     * @param publicKey 발급한 공개 키
     */
    public RSAPublicKeySpec getRsaPublicKeySpec(PublicKey publicKey) {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        } catch (Exception e) {
            throw new EncryptException(ERROR_RSA_PUBLIC_KEY_SPEC);
        }
    }

    /**
     * RSA 암호화 문 복호화
     *
     * @param privateKey  개인 키
     * @param encryptText 암호화 문
     */
    public byte[] decrypt(PrivateKey privateKey, String encryptText) {
        if (Objects.isNull(encryptText)) {
            throw new EncryptException(ERROR_RSA_ENCRYPT_DECRYPT);
        }

        try {
            @SuppressWarnings("all") final Cipher cipher = Cipher.getInstance(RSA_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(hexToByteArray(encryptText));
        } catch (Exception e) {
            throw new EncryptException(ERROR_RSA_ENCRYPT_DECRYPT);
        }
    }

    private static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() % TWO != ZERO) {
            return new byte[]{};
        }

        byte[] bytes = new byte[hex.length() / TWO];

        for (int i = ZERO; i < hex.length(); i += TWO) {
            byte value = (byte) Integer.parseInt(hex.substring(i, i + TWO), RADIX);
            bytes[(int) Math.floor((double) i / TWO)] = value;
        }

        return bytes;
    }

}
