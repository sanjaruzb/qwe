package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static java.util.Optional.ofNullable;

/**
 * Common crypto-session for CAM-RS methods.
 *
 * Uses algorithms:
 * JWA ECDH-ES key agreement
 * JWA A128GCM encryption
 *
 * Uses JOSE formats:
 * JWK for ephemeral public keys
 * JWE compact serialization
 *
 * Note 1: Interface is stateful and implementations are assumed not thread-safe.
 *
 * Note 2: You must clear any parameter object or method result after use if
 *         it contains critical data like cvc2, pin code, etc.
 *
 * Note 3: No key clearing required (including ephemeral EC keys and content encryption key).
 */
public interface CryptoSession extends SecureObject {


    @Nonnull CryptoSession setJweProducerName(@Nonnull SecureString producerName);


    @Nonnull CryptoSession setJweConsumerName(@Nonnull SecureString consumerName);


    @Nonnull CryptoSession generateEphemeralKeyPair();


    /**
     * SecureJson is used only for consistency of interface.
     * There is no requirement to clear ephemeral key pair from memory.
     *
     * @return copy of public key in JWK
     */
    @Nonnull SecureJson exportEphemeralPublicKeyAsJwk();


    @Nonnull CryptoSession generateContentEncryptionKey(@Nonnull SecureJson theirEphemeralPublicKeyAsJwk);

    /**
     * Get copy of CEK to save it in persistent storage (if required).
     * @return CEK, call after {@link #generateContentEncryptionKey}
     */
    @Nonnull BytesRef exportContentEncryptionKey();

    /**
     * Restore CEK from persistent storage (if used).
     */
    @SuppressWarnings("UnusedReturnValue")
    @Nonnull CryptoSession setContentEncryptionKey(@Nonnull BytesRef contentEncryptionKey);


    /**
     * Call when the session is over.
     * Should clear all the state of session.
     */
    @Override
    void clear();



    @Nonnull Jwe jwe();

    interface Jwe {


        // API for JWE generation

        @Nonnull Jwe setHeader(@Nonnull String name, @Nonnull SecureString value);


        @Nonnull Jwe setPayload(@Nonnull SecureJson json);


        @Nonnull SecureString getCompactSerialization();



        // API for JWE parsing

        @Nonnull Jwe setCompactSerialization(@Nonnull SecureString value);


        @Nullable SecureString getHeader(@Nonnull String name);


        default @Nullable SecureB64u getHeaderAsB64u(@Nonnull String name) {
            return ofNullable(getHeader(name)).map(SecureB64u::copy).orElse(null);
        }


        @Nonnull SecureJson getPayload();



        // JWE cleanup API

        @Nonnull Jwe clear();

    }

}
