package org.wallentines.jwt.impl;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.wallentines.jwt.Algorithm;
import org.wallentines.jwt.JsonWebKey;
import org.wallentines.jwt.KeyType;
import org.wallentines.jwt.impl.KeyValues.OctetSequence;

public class SignatureUtil {

    public static byte[] generateHmac(byte[] data, byte[] key, Algorithm alg) throws GeneralSecurityException {

        String algorithmName = switch(alg) {
            case HS256 -> "HmacSHA256";
            case HS384 -> "HmacSHA384";
            case HS512 -> "HmacSHA512";
            default -> throw new IllegalArgumentException("Invalid algorithm for HMAC generation");
        };

        Mac mac = Mac.getInstance(algorithmName);
        mac.init(new SecretKeySpec(key, algorithmName));
        return mac.doFinal(data);
    }

    private static String getAsymmetricAlgorithmName(Algorithm alg) {
        return switch(alg) {
            case RS256 -> "SHA256withRSA";
            case RS384 -> "SHA384withRSA";
            case RS512 -> "SHA512withRSA";
            case ES256 -> "SHA256withECDSA";
            case ES384 -> "SHA384withECDSA";
            case ES512 -> "SHA512withECDSA";
            case PS256, PS384, PS512 -> "RSASSA-PSS";
            default -> throw new IllegalArgumentException("Invalid algorithm for asymmetric signing");
        };
    }
    private static void applyParameter(Signature sig, Algorithm alg) throws GeneralSecurityException {

        sig.setParameter(new java.security.spec.PSSParameterSpec(
            switch(alg) {
                case PS256 -> "SHA-256";
                case PS384 -> "SHA-384";
                case PS512 -> "SHA-512";
                default -> throw new IllegalArgumentException("Invalid algorithm for PSS signing");
            },
            "MGF1",
            switch(alg) {
                case PS256 -> MGF1ParameterSpec.SHA256;
                case PS384 -> MGF1ParameterSpec.SHA384;
                case PS512 -> MGF1ParameterSpec.SHA512;
                default -> throw new IllegalArgumentException("Invalid algorithm for PSS signing");
            },
            32,
            1
        ));

    }

    public static byte[] signAsymmetric(byte[] data, PrivateKey key, Algorithm alg) throws GeneralSecurityException {

        String algorithmName = getAsymmetricAlgorithmName(alg);

        Signature signature = Signature.getInstance(algorithmName);
        if(alg == Algorithm.PS256 || alg == Algorithm.PS384 || alg == Algorithm.PS512) {
            applyParameter(signature, alg);
        }
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifyAsymmetric(byte[] data, byte[] signatureBytes, PublicKey key, Algorithm alg) throws GeneralSecurityException {
        String algorithmName = getAsymmetricAlgorithmName(alg);

        Signature signature = Signature.getInstance(algorithmName);
        if(alg == Algorithm.PS256 || alg == Algorithm.PS384 || alg == Algorithm.PS512) {
            applyParameter(signature, alg);
        }
        signature.initVerify(key);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static byte[] sign(byte[] data, JsonWebKey key, Algorithm alg) throws GeneralSecurityException {

        switch(alg) {
            case HS256, HS384, HS512 -> {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("Invalid key type for HMAC signing");
                }
                OctetSequence octetKey = (OctetSequence) key.value();
                return generateHmac(data, octetKey.data(), alg);
            }
            case RS256, RS384, RS512, PS256, PS384, PS512 -> {
                if(key.type() != KeyType.RSA) {
                    throw new IllegalArgumentException("Invalid key type for RSA signing");
                }
                PrivateKey privKey = ((KeyValues.Rsa) key.value()).key();
                return signAsymmetric(data, privKey, alg);
            }
            case ES256, ES384, ES512 -> {
                if(key.type() != KeyType.ELLIPTIC_CURVE) {
                    throw new IllegalArgumentException("Invalid key type for EC signing");
                }
                PrivateKey privKey = ((KeyValues.Ec) key.value()).key();
                return signAsymmetric(data, privKey, alg);
            }
            default -> {
                throw new IllegalArgumentException("Unsupported algorithm for signing: " + alg);
            }
        }
    }

    public static boolean verify(byte[] data, byte[] signature, JsonWebKey key, Algorithm alg) throws GeneralSecurityException {

        switch(alg) {
            case HS256, HS384, HS512 -> {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("Invalid key type for HMAC verification");
                }
                OctetSequence octetKey = (OctetSequence) key.value();
                try {
                    byte[] expectedSignature = generateHmac(data, octetKey.data(), alg);
                    return Arrays.equals(expectedSignature, signature);
                } catch (GeneralSecurityException e) {
                    throw new RuntimeException("Failed to verify HMAC signature", e);
                }
            }
            case RS256, RS384, RS512, PS256, PS384, PS512 -> {
                if(key.type() != KeyType.RSA) {
                    throw new IllegalArgumentException("Invalid key type for RSA verification");
                }
                PublicKey pubKey = ((KeyValues.Rsa) key.value()).pub();
                return verifyAsymmetric(data, signature, pubKey, alg);
            }
            case ES256, ES384, ES512 -> {
                if(key.type() != KeyType.ELLIPTIC_CURVE) {
                    throw new IllegalArgumentException("Invalid key type for EC verification");
                }
                PublicKey pubKey = ((KeyValues.Ec) key.value()).pub();
                return verifyAsymmetric(data, signature, pubKey, alg);
            }
            default -> {
                throw new IllegalArgumentException("Unsupported algorithm for signing: " + alg);
            }
        }

    }

}
