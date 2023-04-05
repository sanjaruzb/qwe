package ru.ftc.cs.cam_rs.crypto.session;

import ru.ftc.cs.cam_rs.crypto.session.cmn.*;

import javax.annotation.Nonnull;

import static java.util.Objects.isNull;
import static ru.ftc.cs.cam_rs.crypto.session.cmn.CryptoSessionException.checkNonNull;

/**
 * Crypto session for set-pin method of CAM-RS
 */
public class SetPinCryptoSession implements SecureObject {


    private final CryptoSession cryptoSessionDelegate;

    @SuppressWarnings("unused")
    public SetPinCryptoSession() {
        this(new CryptoSessionDefault());
    }

    public SetPinCryptoSession(@Nonnull CryptoSession cryptoSessionDelegate) {

        this.cryptoSessionDelegate = cryptoSessionDelegate;

        this.cryptoSessionDelegate
                .setJweConsumerName(SecureString.copy("CardStandard"))
                .generateEphemeralKeyPair();
    }


    private SecureString sessionId;

    public SetPinCryptoSession setSessionId(@Nonnull SecureString sessionId) {
        this.sessionId = sessionId;
        this.cryptoSessionDelegate.setJweProducerName(sessionId);
        return this;
    }


    public @Nonnull SecureJson exportEphemeralPublicKeyAsJwk() {
        return cryptoSessionDelegate.exportEphemeralPublicKeyAsJwk();
    }


    public @Nonnull SetPinCryptoSession generateContentEncryptionKey(@Nonnull SecureJson theirEphemeralPublicKeyAsJwk) {
        cryptoSessionDelegate.generateContentEncryptionKey(theirEphemeralPublicKeyAsJwk);
        return this;
    }

    public @Nonnull BytesRef exportContentEncryptionKey() {
        return cryptoSessionDelegate.exportContentEncryptionKey();
    }

    public @Nonnull SetPinCryptoSession setContentEncryptionKey(@Nonnull BytesRef contentEncryptionKey) {
        cryptoSessionDelegate.setContentEncryptionKey(contentEncryptionKey);
        return this;
    }



    public @Nonnull SecureString createJwe(@Nonnull SecureJson payload) {

        checkNonNull("sessionId", sessionId);

        return cryptoSessionDelegate
                .jwe()
                .setHeader("ssn", sessionId)
                .setPayload(payload)
                .getCompactSerialization();
    }


    /**
     * @return payload json
     */
    public @Nonnull SecureJson parseJwe(@Nonnull SecureString compactSerializedJwe) {

        checkNonNull("sessionId", sessionId);

        CryptoSession.Jwe jwe = cryptoSessionDelegate.jwe().setCompactSerialization(compactSerializedJwe);

        SecureString ssn = jwe.getHeader("ssn");
        if (isNull(ssn) || !ssn.equals(sessionId)) {
            throw new CryptoSessionException("'ssn' header mismatch", null);
        }

        return jwe.getPayload();
    }



    @Override
    public void clear() {
        cryptoSessionDelegate.clear();
    }

}
