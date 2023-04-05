package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static ru.ftc.cs.cam_rs.crypto.session.cmn.CryptoSessionException.checkNonNull;

public class CryptoSessionDefault implements CryptoSession {

    private static final SecureString EC      = SecureString.copy("EC");
    private static final SecureString P_256   = SecureString.copy("P-256");
    private static final SecureString A128GCM = SecureString.copy("A128GCM");
    private static final SecureString DOT     = SecureString.copy(".");



    private SecureString producerName = null;
    private SecureString consumerName = null;

    @Override
    public @Nonnull CryptoSession setJweProducerName(@Nonnull SecureString producerName) {
        this.producerName = producerName;
        return this;
    }

    @Override
    public @Nonnull CryptoSession setJweConsumerName(@Nonnull SecureString consumerName) {
        this.consumerName = consumerName;
        return this;
    }



    private ECPrivateKey ownEphemPrivateKey = null;
    private ECPublicKey  ownEphemPublicKey  = null;

    @Override
    public @Nonnull CryptoSession generateEphemeralKeyPair() {
        try {
            for (int ii = 0; ii < 100; ii++) {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                this.ownEphemPrivateKey = (ECPrivateKey) keyPair.getPrivate();
                this.ownEphemPublicKey  = (ECPublicKey)  keyPair.getPublic();

                boolean pvtKeyLen32 = ownEphemPrivateKey.getS().toByteArray().length == 32;
                boolean pubKeyXLen32 = ownEphemPublicKey.getW().getAffineX().toByteArray().length == 32;
                boolean pubKeyYLen32 = ownEphemPublicKey.getW().getAffineY().toByteArray().length == 32;

                if (pvtKeyLen32 && pubKeyXLen32 && pubKeyYLen32) {
                    return this;
                }
            }

            this.ownEphemPrivateKey = null;
            this.ownEphemPublicKey  = null;

            throw new CryptoSessionException("Failed to generate EC key pair. No more retries");
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new CryptoSessionException("Failed to generate EC key pair", e);
        }
    }



    @Override
    public @Nonnull SecureJson exportEphemeralPublicKeyAsJwk() {

        checkNonNull("ownEphemPublicKey", ownEphemPublicKey);

        byte[] xBytes = ownEphemPublicKey.getW().getAffineX().toByteArray();
        byte[] yBytes = ownEphemPublicKey.getW().getAffineY().toByteArray();

        // no need to clear all wrapped/copied objects:

        return SecureJson.copy(
                "kty", EC,
                "crv", P_256,
                "x", SecureB64u.wrap(BytesRef.wrap(xBytes)).copyToString(),
                "y", SecureB64u.wrap(BytesRef.wrap(yBytes)).copyToString());
    }



    private BytesRef contentEncryptionKey = null;

    private static final String CONTENT_ENCRYPTION_KEY = "contentEncryptionKey";

    public @Nonnull CryptoSession generateContentEncryptionKey(@Nonnull SecureJson theirEphemeralPublicKeyAsJwk) {

        checkNonNull("producerName", producerName);
        checkNonNull("consumerName", consumerName);
        checkNonNull("ownEphemPrivateKey", ownEphemPrivateKey);

        try {

            ByteArrayOutputStream otherInfoStream = new ByteArrayOutputStream(128);
            // no algorithm id:
            otherInfoStream.write(bytesOfInt(0));
            // partyUInfo - producer info:
            otherInfoStream.write(bytesWithLenPrefix(producerName.copyToBytesRef(UTF_8)));
            // partyVInfo - consumer info:
            otherInfoStream.write(bytesWithLenPrefix(consumerName.copyToBytesRef(UTF_8)));
            // key data length:
            otherInfoStream.write(bytesOfInt(256));
            byte[] otherInfoBytes = otherInfoStream.toByteArray();

            ECPublicKey theirPublicKey = parseEcPublicKeyJwk(theirEphemeralPublicKeyAsJwk);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ownEphemPrivateKey);
            keyAgreement.doPhase(theirPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytesOfInt(1));
            md.update(sharedSecret);
            md.update(otherInfoBytes);

            // we need only 16 bytes for A128GCM
            contentEncryptionKey = BytesRef.wrap(md.digest(), 0, 16);

            // throws exception for EC key :(
            // ownPrivateKey.destroy()

            return this;

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CryptoSessionException("Failed to generate CEK", e);
        }
    }

    private static byte[] bytesOfInt(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    private static byte[] bytesWithLenPrefix(@Nonnull BytesRef src) {
        return ByteBuffer.allocate(src.getLength() + 4)
                .putInt(src.getLength())
                .put(src.wrapToBuffer())
                .array();
    }

    public @Nonnull BytesRef exportContentEncryptionKey() {
        checkNonNull(CONTENT_ENCRYPTION_KEY, contentEncryptionKey);

        return contentEncryptionKey.copy();
    }

    @Override
    public @Nonnull CryptoSession setContentEncryptionKey(@Nonnull BytesRef contentEncryptionKey) {
        this.contentEncryptionKey = contentEncryptionKey.copy();
        return this;
    }


    @Override
    public void clear() {

        ownEphemPrivateKey = null;
        ownEphemPublicKey = null;

        consumerName = null;
        producerName = null;

        contentEncryptionKey = null;

        jwe.clear();
    }



    private final Jwe jwe = new Jwe();

    @Override
    public @Nonnull CryptoSession.Jwe jwe() {
        return jwe;
    }

    private class Jwe implements CryptoSession.Jwe {


        private final Map<String, Object> headers = new LinkedHashMap<>();

        @Override
        public @Nonnull CryptoSession.Jwe setHeader(@Nonnull String name, @Nonnull SecureString value) {
            headers.compute(name, (s, old) -> {
                if (old instanceof SecureString) {
                    ((SecureString) old).clear();
                }
                return value;
            });
            return this;
        }

        @Override
        public @Nullable SecureString getHeader(@Nonnull String name) {
            return (SecureString) headers.get(name);
        }

        private void clearHeaders() {
            headers.forEach((s, o) -> {
                if (o instanceof SecureObject) {
                    ((SecureObject) o).clear();
                }
            });
            headers.clear();
        }



        // UTF-8 bytes
        private BytesRef payload = null;

        @Override
        public @Nonnull CryptoSession.Jwe setPayload(@Nonnull SecureJson json) {

            clearPayload();
            clearCompactSerialization();

            payload = json.getString().copyToBytesRef(UTF_8);
            return this;
        }

        @Override
        public @Nonnull SecureJson getPayload() {

            checkNonNull("compactSerialization", compactSerialization);
            checkNonNull(CONTENT_ENCRYPTION_KEY, contentEncryptionKey);

            try {
                if (isNull(payload)) {

                    int authTagBitsCount = 128;

                    List<SecureString> jweParts = compactSerialization.split('.');

                    if (jweParts.size() != 5) {
                        throw new IllegalArgumentException("Number of jwe parts must be 5");
                    }

                    // clear all objects in close()
                    try (BytesRef aad = jweParts.get(0).copyToBytesRef(US_ASCII);

                         BytesRef iv = SecureB64u.copy(jweParts.get(2)).getBytesRef();

                         BytesRef cipherText = SecureB64u.copy(jweParts.get(3)).getBytesRef();

                         BytesRef authTag = SecureB64u.copy(jweParts.get(4)).getBytesRef();

                         BytesRef encryptResult = cipherText.copyConcat(authTag)) {

                        this.payload = decryptAesGcm(authTagBitsCount, contentEncryptionKey, iv, aad, encryptResult);
                    }
                }

                return SecureJson.copy(payload);

            } catch (Exception e) {
                throw new CryptoSessionException("Failed to get payload JWE", e);
            }
        }

        private void clearPayload() {
            if (nonNull(payload)) {
                payload.clear();
            }
            payload = null;
        }



        private SecureString compactSerialization = null;

        @Override
        public @Nonnull CryptoSession.Jwe setCompactSerialization(@Nonnull SecureString value) {
            try {
                List<SecureString> jweParts = value.split('.');

                if (jweParts.size() != 5) {
                    throw new IllegalArgumentException("Number of jwe parts must be 5");
                }

                try (SecureB64u headerB64u = SecureB64u.copy(jweParts.get(0))) {

                    clear();

                    SecureJson headerJson = SecureJson.copy(headerB64u.getBytesRef());

                    // save the map from headerJson, but JSON string must be cleared

                    headers.putAll(headerJson.getMap());

                    headerJson.getString().clear();

                    if (headers.size() == 0) {
                        throw new IllegalArgumentException("Empty header");
                    }
                    if (!headers.containsKey("enc") || !A128GCM.equals(headers.get("enc"))) {
                        throw new IllegalArgumentException("Unknown encryption method");
                    }

                    compactSerialization = value.copy();
                }

                return this;

            } catch (Exception e) {
                throw new CryptoSessionException("Failed to set JWE compact serialization", e);
            }
        }

        @Override
        public @Nonnull SecureString getCompactSerialization() {

            checkNonNull(CONTENT_ENCRYPTION_KEY, contentEncryptionKey);
            checkNonNull("payload", payload);

            try {
                if (isNull(compactSerialization)) {

                    headers.put("alg", "dir");
                    headers.put("enc", A128GCM.copy());

                    int authTagBitsCount = 128;
                    int authTagBytesCount = authTagBitsCount / 8;

                    try (SecureJson headerJson = SecureJson.copy(headers);

                         BytesRef iv = BytesRef.wrap(new byte[12]).randomize();

                         BytesRef header = headerJson.getString().copyToBytesRef(UTF_8);

                         SecureString headerB64uString = SecureB64u.wrap(header).copyToString();

                         BytesRef aad = headerB64uString.copyToBytesRef(US_ASCII);

                         BytesRef encrypt = encryptAesGcm(authTagBitsCount, contentEncryptionKey, iv, aad, payload);

                         BytesRef cipherText = encrypt.wrap(0, encrypt.getLength() - authTagBytesCount);

                         BytesRef authTag = encrypt.wrap(encrypt.getLength() - authTagBytesCount, authTagBytesCount);

                         SecureString ivB64uString = SecureB64u.wrap(iv).copyToString();

                         SecureString cipherTextB64uString = SecureB64u.wrap(cipherText).copyToString();

                         SecureString authTagB64uString = SecureB64u.wrap(authTag).copyToString()) {

                        compactSerialization = headerB64uString.copyConcat(
                                DOT, // no encrypted key in 'direct' encryption
                                DOT, ivB64uString,
                                DOT, cipherTextB64uString,
                                DOT, authTagB64uString);
                    }
                }

                return compactSerialization.copy();

            } catch (Exception e) {
                throw new CryptoSessionException("Failed to get JWE compact serialization", e);
            }
        }

        private void clearCompactSerialization() {
            if (nonNull(compactSerialization)) {
                compactSerialization.clear();
            }
            compactSerialization = null;
        }



        @Override
        public @Nonnull Jwe clear() {
            clearHeaders();
            clearPayload();
            clearCompactSerialization();

            return this;
        }



        private @Nonnull BytesRef encryptAesGcm(int authTagBitsCount,
                                                @Nonnull BytesRef cek,
                                                @Nonnull BytesRef iv,
                                                @Nonnull BytesRef aadBytes,
                                                @Nonnull BytesRef data) {
            // result included cipher text and auth tag
            return doAesGcmCipher(Cipher.ENCRYPT_MODE, authTagBitsCount, cek, iv, aadBytes, data);
        }

        private @Nonnull BytesRef decryptAesGcm(int authTagBitsCount,
                                                @Nonnull BytesRef cek,
                                                @Nonnull BytesRef iv,
                                                @Nonnull BytesRef aadBytes,
                                                @Nonnull BytesRef encryptResult/*result of encryptData, included cipher text and auth tag*/) {
            return doAesGcmCipher(Cipher.DECRYPT_MODE, authTagBitsCount, cek, iv, aadBytes, encryptResult);
        }

        private @Nonnull BytesRef doAesGcmCipher(int mode,
                                                 int authTagBitsCount,
                                                 @Nonnull BytesRef cek,
                                                 @Nonnull BytesRef iv,
                                                 @Nonnull BytesRef aad,
                                                 @Nonnull BytesRef input) {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NOPADDING");

                SecretKeySpec key = new SecretKeySpec(cek.getBytes(), cek.getOffset(), cek.getLength(), "AES");

                GCMParameterSpec params = new GCMParameterSpec(authTagBitsCount, iv.getBytes(), iv.getOffset(), iv.getLength());

                cipher.init(mode, key, params);

                cipher.updateAAD(aad.getBytes(), aad.getOffset(), aad.getLength());

                return BytesRef.wrap(cipher.doFinal(input.getBytes(), input.getOffset(), input.getLength()));

            } catch (GeneralSecurityException e) {
                throw new CryptoSessionException("Failed to cipher", e);
            }
        }
    }



    private static final ECParameterSpec P_256_SPEC = new ECParameterSpec(
            new EllipticCurve(
                    new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
                    new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                    new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")),
            new ECPoint(
                    new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                    new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")),
            new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
            1);

    private static @Nonnull ECPublicKey parseEcPublicKeyJwk(@Nonnull SecureJson ecPublicKeyJwk) {
        try {
            Map<String, Object> jwkMap = ecPublicKeyJwk.getMap();

            if (!jwkMap.containsKey("crv") || !P_256.equals(jwkMap.get("crv"))) {
                throw new IllegalArgumentException("Unknown curve name in ephemeral public key");
            }

            // clear() on ephemeral key is not required

            BytesRef xBytesRef = SecureB64u.copy((SecureString) jwkMap.get("x")).getBytesRef();
            BytesRef yBytesRef = SecureB64u.copy((SecureString) jwkMap.get("y")).getBytesRef();

            BigInteger x = new BigInteger(xBytesRef.copy().getBytes());
            BigInteger y = new BigInteger(yBytesRef.copy().getBytes());

            ECPoint epkPoint = new ECPoint(x, y);
            ECPublicKeySpec epkSpec = new ECPublicKeySpec(epkPoint, P_256_SPEC);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(epkSpec);

        } catch (Exception e) {
            throw new CryptoSessionException("Failed to parse JWK", e);
        }
    }

}
