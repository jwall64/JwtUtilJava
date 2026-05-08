package org.wallentines.jwt.impl;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.EnumSet;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.wallentines.jwt.Algorithm;
import org.wallentines.jwt.CryptAlgorithm;
import org.wallentines.jwt.EcCurve;
import org.wallentines.jwt.JsonWebKey;
import org.wallentines.jwt.KeyOperation;
import org.wallentines.jwt.KeyType;
import org.wallentines.jwt.KeyUse;
import org.wallentines.jwt.KeyVerifier;
import org.wallentines.jwt.impl.KeyValues.Ec;
import org.wallentines.jwt.impl.KeyValues.OctetSequence;
import org.wallentines.mdcfg.ConfigSection;

public class CekUtil {

    public record GeneratedCek(byte[] cek, byte[] encryptedCek) { }

    private static byte[] deriveEcdh(Ec pub, Ec priv, Algorithm alg, CryptAlgorithm crypt) throws GeneralSecurityException {

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(priv.key());
        agreement.doPhase(pub.pub(), true);

        byte[] sharedSecret = agreement.generateSecret();
        int keyLen = switch(alg) {
            case ECDH_ES -> crypt.keyLength();
            case ECDH_ES_A128KW -> 16;
            case ECDH_ES_A192KW -> 24;
            case ECDH_ES_A256KW -> 32;
            default -> throw new IllegalArgumentException("Unsupported ECDH encryption algorithm: " + alg);
        };

        if(sharedSecret.length < keyLen) throw new IllegalArgumentException("Not enough key bytes!");

        byte[] out = new byte[keyLen];
        System.arraycopy(sharedSecret, 0, out, 0, keyLen);
        return out;
    }

    public static GeneratedCek generateCek(ConfigSection header, JsonWebKey key, Algorithm alg, CryptAlgorithm crypt, KeyVerifier verifier) throws GeneralSecurityException {
        if(alg.use() != KeyUse.ENCRYPTION) {
            throw new IllegalArgumentException("Algorithm is not an encryption algorithm");
        }

        switch(alg) {
            default: throw new IllegalArgumentException("Unsupported encryption algorithm: " + alg);
            case RSA1_5, RSA_OAEP, RSA_OAEP_256: {
                if(key.type() != KeyType.RSA) {
                    throw new IllegalArgumentException("RSA encryption requires an RSA key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.WRAP_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }

                byte[] cek = new byte[crypt.keyLength()];
                new SecureRandom().nextBytes(cek);

                KeyValues.Rsa rsaKey = (KeyValues.Rsa) key.value();
                Cipher cipher = switch(alg) {
                    case RSA1_5 -> Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    case RSA_OAEP -> Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                    case RSA_OAEP_256 -> Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    default -> throw new IllegalArgumentException("Unsupported RSA encryption algorithm: " + alg);
                };
                cipher.init(Cipher.ENCRYPT_MODE, rsaKey.pub());
                return new GeneratedCek(cek, cipher.doFinal(cek));
            }

            case A128KW, A192KW, A256KW: {
                if(key.type() != org.wallentines.jwt.KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("AES key wrap encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.WRAP_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }

                byte[] cek = new byte[crypt.keyLength()];
                new SecureRandom().nextBytes(cek);

                Cipher cipher = Cipher.getInstance("AESWrap");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(((OctetSequence) key.value()).data(), "AES"));
                return new GeneratedCek(cek, cipher.doFinal(cek));
            }

            case DIRECT: {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("Direct encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.ENCRYPT)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }
                OctetSequence octetKey = (OctetSequence) key.value();
                byte[] keyBytes = octetKey.data();

                return new GeneratedCek(keyBytes, new byte[0]);
            }

            case ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW: {
                if(key.type() != org.wallentines.jwt.KeyType.ELLIPTIC_CURVE) {
                    throw new IllegalArgumentException("ECDH encryption requires an EC key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.DERIVE_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }

                EcCurve curve = switch(alg) {
                    case ECDH_ES, ECDH_ES_A128KW -> EcCurve.P256;
                    case ECDH_ES_A192KW -> EcCurve.P384;
                    case ECDH_ES_A256KW -> EcCurve.P521;
                    default -> throw new IllegalArgumentException("Unsupported ECDH encryption algorithm: " + alg);
                };

                Ec ephKey;
                if(header.has("epk")) {
                    JsonWebKey epk = header.get("epk", JsonWebKey.SERIALIZER);
                    if(epk.type() != KeyType.ELLIPTIC_CURVE) {
                        throw new IllegalArgumentException("Ephemeral key must be an EC key");
                    }
                    ephKey = (Ec) epk.value();
                    if(ephKey.curve() != curve) {
                        throw new IllegalArgumentException("Ephemeral key curve does not match algorithm requirements");
                    }
                } else {
                    KeyPair eph = curve.generateKeyPair();
                    ephKey = new Ec(curve, (ECPublicKey) eph.getPublic(), (ECPrivateKey) eph.getPrivate());
                    header.set("epk", new JsonWebKey(
                        new JsonWebKey.Meta(KeyUse.ENCRYPTION, EnumSet.of(KeyOperation.DERIVE_KEY), alg, null, null, null, null, null),
                        ephKey.withoutPrivate()
                    ), JsonWebKey.SERIALIZER);
                }

                byte[] sharedSecret = deriveEcdh(((Ec) key.value()), ephKey, alg, crypt);

                Algorithm algorithm = switch(alg) {
                    case ECDH_ES -> Algorithm.DIRECT;
                    case ECDH_ES_A128KW -> Algorithm.A128KW;
                    case ECDH_ES_A192KW -> Algorithm.A192KW;
                    case ECDH_ES_A256KW -> Algorithm.A256KW;
                    default -> throw new IllegalArgumentException("Unsupported ECDH encryption algorithm: " + alg);
                };
                return generateCek(
                    header, 
                    new JsonWebKey(
                        new JsonWebKey.Meta(KeyUse.ENCRYPTION,
                                EnumSet.of(algorithm == Algorithm.DIRECT
                                        ? KeyOperation.ENCRYPT
                                        : KeyOperation.WRAP_KEY),
                                algorithm, null, null, null, null, null),
                        new KeyValues.OctetSequence(sharedSecret)
                    ), 
                    algorithm,
                    crypt,
                    verifier
                );
            }

            case A128GCMKW, A192GCMKW, A256GCMKW: {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("AES-GCM key wrap encryption requires an octet sequence key");
                }

                byte[] cek = new byte[crypt.keyLength()];
                new SecureRandom().nextBytes(cek);

                byte[] iv;
                if(header.has("iv")) {
                    iv = header.get("iv", ExtraSerializers.BYTE_ARRAY);
                    if(iv.length != 12) {
                        throw new IllegalArgumentException("Invalid IV length for AES-GCM key wrap: " + iv.length);
                    }
                } else {
                     iv = new byte[12];
                    new SecureRandom().nextBytes(iv);
                    header.set("iv", iv, ExtraSerializers.BYTE_ARRAY);
                }


                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, 
                    new SecretKeySpec(((OctetSequence) key.value()).data(), "AES"), 
                    new GCMParameterSpec(128, iv));

                byte[] combined = cipher.doFinal(cek);

                byte[] encryptedCek = new byte[combined.length - 16];
                byte[] tag = new byte[16];
                System.arraycopy(combined, 0, encryptedCek, 0, encryptedCek.length);
                System.arraycopy(combined, encryptedCek.length, tag, 0, tag.length);

                header.set("tag", tag, ExtraSerializers.BYTE_ARRAY);

                return new GeneratedCek(cek, encryptedCek);
            }

            case PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW: {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("PBES2 encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.DERIVE_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }

                byte[] salt;
                if(header.has("p2s")) {
                    salt = header.get("p2s", ExtraSerializers.BYTE_ARRAY);
                    if(salt == null || salt.length == 0) {
                        throw new IllegalArgumentException("PBES2 encryption requires a non-empty salt");
                    }
                } else {
                    salt = new byte[16];
                    new SecureRandom().nextBytes(salt);
                    header.set("p2s", salt, ExtraSerializers.BYTE_ARRAY);
                }
                int iterations = 10000 + new SecureRandom().nextInt(10000);
                if(header.has("p2c")) {
                    iterations = header.getNumber("p2c").intValue();
                    if(iterations <= 0) {
                        throw new IllegalArgumentException("PBES2 encryption requires a positive iteration count");
                    }
                } else {
                    header.set("p2c", iterations);
                }

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmac" + switch(alg) {
                    case PBES2_HS256_A128KW -> "SHA256";
                    case PBES2_HS384_A192KW -> "SHA384";
                    case PBES2_HS512_A256KW -> "SHA512";
                    default -> throw new IllegalArgumentException("Unsupported PBES2 encryption algorithm: " + alg);
                });
                PBEKeySpec spec = new PBEKeySpec(
                    new String(((OctetSequence) key.value()).data(), StandardCharsets.UTF_8).toCharArray(), 
                    salt, 
                    iterations, 
                    switch(alg) {
                        case PBES2_HS256_A128KW -> 128;
                        case PBES2_HS384_A192KW -> 192;
                        case PBES2_HS512_A256KW -> 256;
                        default -> throw new IllegalArgumentException("Unsupported PBES2 encryption algorithm: " + alg);
                    }
                );

                byte[] wrapKey = factory.generateSecret(spec).getEncoded();

                Algorithm algorithm = switch(alg) {
                    case PBES2_HS256_A128KW -> Algorithm.A128KW;
                    case PBES2_HS384_A192KW -> Algorithm.A192KW;
                    case PBES2_HS512_A256KW -> Algorithm.A256KW;
                    default -> throw new IllegalArgumentException("Unsupported PBES2 encryption algorithm: " + alg);
                };
                return generateCek(
                    header, 
                    new JsonWebKey(
                        new JsonWebKey.Meta(KeyUse.ENCRYPTION, EnumSet.of(KeyOperation.WRAP_KEY), algorithm, null, null, null, null, null), 
                        new KeyValues.OctetSequence(wrapKey)
                    ), 
                    algorithm,
                    crypt,
                    verifier
                );

            }
        }
    }

 
    public static byte[] getCek(byte[] encryptedCek, ConfigSection header, JsonWebKey key, Algorithm alg, CryptAlgorithm enc, KeyVerifier verifier) throws GeneralSecurityException {
        
        if(alg.use() != KeyUse.ENCRYPTION) {
            throw new IllegalArgumentException("Algorithm is not an encryption algorithm");
        }

        switch(alg) {
            default: throw new IllegalArgumentException("Unsupported encryption algorithm: " + alg);
            case RSA1_5, RSA_OAEP, RSA_OAEP_256: {
                if(key.type() != KeyType.RSA) {
                    throw new IllegalArgumentException("RSA encryption requires an RSA key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.UNWRAP_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }
                KeyValues.Rsa rsaKey = (KeyValues.Rsa) key.value();
                Cipher cipher = switch(alg) {
                    case RSA1_5 -> Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    case RSA_OAEP -> Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                    case RSA_OAEP_256 -> Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    default -> throw new IllegalArgumentException("Unsupported RSA encryption algorithm: " + alg);
                };
                cipher.init(Cipher.DECRYPT_MODE, rsaKey.key());
                return cipher.doFinal(encryptedCek);
            }

            case A128KW, A192KW, A256KW: {
                if(key.type() != org.wallentines.jwt.KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("AES key wrap encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.UNWRAP_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }
                Cipher cipher = Cipher.getInstance("AESWrap");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(((OctetSequence) key.value()).data(), "AES"));
                return cipher.doFinal(encryptedCek);
            }

            case DIRECT: {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("Direct encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.DECRYPT)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }
                OctetSequence octetKey = (OctetSequence) key.value();
                return octetKey.data();
            }

            case ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW: {
                if(key.type() != org.wallentines.jwt.KeyType.ELLIPTIC_CURVE) {
                    throw new IllegalArgumentException("ECDH encryption requires an EC key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.DERIVE_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }
                JsonWebKey epk = header.get("epk", JsonWebKey.SERIALIZER);

                Ec eph = (Ec) epk.value();
                Ec ekey = (Ec) key.value();

                if(eph.curve() != ekey.curve()) {
                    throw new IllegalArgumentException("Curves do not match!");
                }

                byte[] sharedSecret = deriveEcdh(eph, ekey, alg, enc);

                Algorithm algorithm =
                    switch(alg) {
                        case ECDH_ES -> Algorithm.DIRECT;
                        case ECDH_ES_A128KW -> Algorithm.A128KW;
                        case ECDH_ES_A192KW -> Algorithm.A192KW;
                        case ECDH_ES_A256KW -> Algorithm.A256KW;
                        default -> throw new IllegalArgumentException("Unsupported ECDH encryption algorithm: " + alg);
                    };
                return getCek(
                    encryptedCek, 
                    header, 
                    new JsonWebKey(
                        new JsonWebKey.Meta(KeyUse.ENCRYPTION,
                                EnumSet.of(algorithm == Algorithm.DIRECT
                                        ? KeyOperation.DECRYPT
                                        : KeyOperation.UNWRAP_KEY),
                                algorithm, null, null, null, null, null),
                        new KeyValues.OctetSequence(sharedSecret)
                    ),
                    algorithm,
                    enc,
                    verifier
                );
            }

            case A128GCMKW, A192GCMKW, A256GCMKW: {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("AES-GCM key wrap encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.UNWRAP_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }

                byte[] iv = header.get("iv", ExtraSerializers.BYTE_ARRAY);
                if(iv.length != 12) {
                    throw new IllegalArgumentException("Invalid IV length for AES-GCM key wrap: " + iv.length);
                }

                byte[] tag = header.get("tag", ExtraSerializers.BYTE_ARRAY);
                if(tag.length != 16) {
                    throw new IllegalArgumentException("Invalid tag length for AES-GCM key wrap: " + tag.length);
                }

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, 
                    new SecretKeySpec(((OctetSequence) key.value()).data(), "AES"), 
                    new GCMParameterSpec(128, iv));

                byte[] combined = new byte[encryptedCek.length + tag.length];
                System.arraycopy(encryptedCek, 0, combined, 0, encryptedCek.length);
                System.arraycopy(tag, 0, combined, encryptedCek.length, tag.length);

                return cipher.doFinal(combined);
            }

            case PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW: {
                if(key.type() != KeyType.OCTET_SEQUENCE) {
                    throw new IllegalArgumentException("PBES2 encryption requires an octet sequence key");
                }
                if(!verifier.verify(key, alg, KeyUse.ENCRYPTION, KeyOperation.DERIVE_KEY)) {
                    throw new IllegalArgumentException("Key is not valid for the specified algorithm");
                }

                byte[] salt = header.get("p2s", ExtraSerializers.BYTE_ARRAY);
                int iterations = header.getNumber("p2c").intValue();

                if(salt == null || salt.length == 0) {
                    throw new IllegalArgumentException("PBES2 encryption requires a non-empty salt");
                }
                if(iterations <= 0) {
                    throw new IllegalArgumentException("PBES2 encryption requires a positive iteration count");
                }

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmac" + switch(alg) {
                    case PBES2_HS256_A128KW -> "SHA256";
                    case PBES2_HS384_A192KW -> "SHA384";
                    case PBES2_HS512_A256KW -> "SHA512";
                    default -> throw new IllegalArgumentException("Unsupported PBES2 encryption algorithm: " + alg);
                });
                PBEKeySpec spec = new PBEKeySpec(
                    new String(((OctetSequence) key.value()).data(), StandardCharsets.UTF_8).toCharArray(), 
                    salt, 
                    (int) iterations, 
                    switch(alg) {
                        case PBES2_HS256_A128KW -> 128;
                        case PBES2_HS384_A192KW -> 192;
                        case PBES2_HS512_A256KW -> 256;
                        default -> throw new IllegalArgumentException("Unsupported PBES2 encryption algorithm: " + alg);
                    }
                );

                byte[] wrapKey = factory.generateSecret(spec).getEncoded();
                Algorithm algorithm = switch(alg) {
                    case PBES2_HS256_A128KW -> Algorithm.A128KW;
                    case PBES2_HS384_A192KW -> Algorithm.A192KW;
                    case PBES2_HS512_A256KW -> Algorithm.A256KW;
                    default -> throw new IllegalArgumentException("Unsupported PBES2 encryption algorithm: " + alg);
                };
                return getCek(
                    encryptedCek, 
                    header, 
                    new JsonWebKey(
                        new JsonWebKey.Meta(KeyUse.ENCRYPTION, EnumSet.of(KeyOperation.UNWRAP_KEY), algorithm, null, null, null, null, null), 
                        new KeyValues.OctetSequence(wrapKey)
                    ), 
                    algorithm,
                    enc,
                    verifier
                );
            }
        }
    }
   

}
