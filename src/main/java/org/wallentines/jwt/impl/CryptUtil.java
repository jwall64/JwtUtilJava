package org.wallentines.jwt.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.wallentines.jwt.Algorithm;
import org.wallentines.jwt.CryptAlgorithm;

public class CryptUtil {

    public record CryptOutput(byte[] ciphertext, byte[] tag) { }

    public static CryptOutput encryptAesCbcHmac(byte[] plaintext, byte[] keyBytes, byte[] iv, byte[] aad, CryptAlgorithm alg) throws GeneralSecurityException {

        byte[] cryptKey = new byte[keyBytes.length / 2];
        byte[] hashKey = new byte[keyBytes.length / 2];
        System.arraycopy(keyBytes, 0, hashKey, 0, hashKey.length);
        System.arraycopy(keyBytes, hashKey.length, cryptKey, 0, cryptKey.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cryptKey, "AES"), new javax.crypto.spec.IvParameterSpec(iv));

        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] hmac = SignatureUtil.generateHmac(aad, hashKey, switch(alg) {
            case A128CBC_HS256 -> Algorithm.HS256;
            case A192CBC_HS384 -> Algorithm.HS384;
            case A256CBC_HS512 -> Algorithm.HS512;
            default -> throw new IllegalArgumentException("Invalid algorithm for AES-CBC-HMAC encryption");
        });

        return new CryptOutput(ciphertext, hmac);
    }

    public static byte[] decryptAesCbcHmac(byte[] ciphertext, byte[] keyBytes, byte[] iv, byte[] aad, byte[] hmac, CryptAlgorithm alg) throws GeneralSecurityException {

        byte[] cryptKey = new byte[keyBytes.length / 2];
        byte[] hashKey = new byte[keyBytes.length / 2];
        System.arraycopy(keyBytes, 0, hashKey, 0, hashKey.length);
        System.arraycopy(keyBytes, hashKey.length, cryptKey, 0, cryptKey.length);

        byte[] expectedHmac = SignatureUtil.generateHmac(aad, hashKey, switch(alg) {
            case A128CBC_HS256 -> Algorithm.HS256;
            case A192CBC_HS384 -> Algorithm.HS384;
            case A256CBC_HS512 -> Algorithm.HS512;
            default -> throw new IllegalArgumentException("Invalid algorithm for AES-CBC-HMAC decryption");
        });

        if (!java.util.Arrays.equals(hmac, expectedHmac)) {
            throw new GeneralSecurityException("HMAC verification failed");
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cryptKey, "AES"), new javax.crypto.spec.IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    public static CryptOutput encryptAesGcm(byte[] plaintext, byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        cipher.updateAAD(aad);
        
        byte[] cipherText = cipher.doFinal(plaintext);

        byte[] tag = new byte[16];
        System.arraycopy(cipherText, cipherText.length - 16, tag, 0, 16);
        byte[] actualCipherText = new byte[cipherText.length - 16];
        System.arraycopy(cipherText, 0, actualCipherText, 0, actualCipherText.length);

        return new CryptOutput(actualCipherText, tag);
    }

    public static byte[] decryptAesGcm(byte[] ciphertext, byte[] key, byte[] iv, byte[] aad, byte[] tag) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        cipher.updateAAD(aad);

        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);

        return cipher.doFinal(combined);
    }

 
    public static CryptOutput encrypt(byte[] plaintext, byte[] iv, byte[] aad, byte[] cek, CryptAlgorithm alg) throws GeneralSecurityException {


        if(cek.length != alg.keyLength()) {
            throw new IllegalArgumentException("Key length does not match algorithm requirements");
        }
        if(iv.length != alg.ivLength()) {
            throw new IllegalArgumentException("IV length does not match algorithm requirements");
        }

        switch(alg) {
            case A128CBC_HS256, A192CBC_HS384, A256CBC_HS512: {
                return encryptAesCbcHmac(plaintext, cek, iv, aad, alg);
            }
            case A128GCM, A192GCM, A256GCM: {
                return encryptAesGcm(plaintext, cek, iv, aad);
            }
            default: throw new IllegalArgumentException("Unsupported encryption algorithm: " + alg);
        }
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] iv, byte[] aad, byte[] tag, byte[] cek, CryptAlgorithm alg) throws GeneralSecurityException {
        if(cek.length != alg.keyLength()) {
            throw new IllegalArgumentException("Key length does not match algorithm requirements");
        }
        if(iv.length != alg.ivLength()) {
            throw new IllegalArgumentException("IV length does not match algorithm requirements");
        }

        switch(alg) {
            case A128CBC_HS256, A192CBC_HS384, A256CBC_HS512: {
                return decryptAesCbcHmac(ciphertext, cek, iv, aad, tag, alg);
            }
            case A128GCM, A192GCM, A256GCM: {
                return decryptAesGcm(ciphertext, cek, iv, aad, tag);
            }
            default: throw new IllegalArgumentException("Unsupported decryption algorithm: " + alg);
        }

    }

    
}
