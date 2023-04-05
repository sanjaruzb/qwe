package ru.ftc.cs.cam_rs.crypto.session;

import ru.ftc.cs.cam_rs.crypto.session.cmn.*;

import javax.annotation.Nonnull;

import static java.util.Optional.ofNullable;

/**
 * Crypto session for get card info methods of CAM-RS
 */
public class GetCardDataCryptoSession implements SecureObject {


    private final CryptoSession cryptoSessionDelegate;

    @SuppressWarnings("unused")
    public GetCardDataCryptoSession(@Nonnull String xCsOriginatorHttpHeader) {
        this(new CryptoSessionDefault(), xCsOriginatorHttpHeader);
    }

    public GetCardDataCryptoSession(@Nonnull CryptoSession cryptoSessionDelegate,
                                    @Nonnull String xCsOriginatorHttpHeader) {

        this.cryptoSessionDelegate = cryptoSessionDelegate;

        this.cryptoSessionDelegate
                // specify jwe producer/consumer names
                .setJweProducerName(SecureString.copy("CardStandard"))
                .setJweConsumerName(SecureString.copy(xCsOriginatorHttpHeader))
                // generate ephemeral own key now
                .generateEphemeralKeyPair();
    }



    /**
     * Ephemeral public key in JWK encoded to base64url without "=" padding.
     * May be used as value for "pub" parameter directly.
     */
    public @Nonnull SecureB64u exportEphemeralPublicKeyAsJwkInB64u() {
        return cryptoSessionDelegate.exportEphemeralPublicKeyAsJwk().copyToB64u();
    }



    public @Nonnull SecureString createJwe(@Nonnull SecureJson payload,
                                           @Nonnull SecureB64u theirEphemeralPublicKeyAsJwkInB64u) {

        SecureJson ownEphemeralPublicKeyAsJwk = cryptoSessionDelegate.exportEphemeralPublicKeyAsJwk();

        return cryptoSessionDelegate
                .generateContentEncryptionKey(theirEphemeralPublicKeyAsJwkInB64u.copyToJson())
                .jwe()
                .setHeader("pub", ownEphemeralPublicKeyAsJwk.copyToB64u().copyToString())
                .setPayload(payload)
                .getCompactSerialization();
    }



    /**
     * @return payload json
     */
    public @Nonnull SecureJson parseJwe(@Nonnull SecureString compactSerializedJwe) {

        cryptoSessionDelegate.jwe().setCompactSerialization(compactSerializedJwe);

        SecureB64u theirEphemeralPublicKeyAsJwkInB64u = ofNullable(cryptoSessionDelegate.jwe().getHeaderAsB64u("pub"))
                .orElseThrow(() -> new CryptoSessionException("'pub' header must be present in JWE object", null));

        return cryptoSessionDelegate
                .generateContentEncryptionKey(theirEphemeralPublicKeyAsJwkInB64u.copyToJson())
                .jwe()
                .getPayload();
    }



    @Override
    public void clear() {
        cryptoSessionDelegate.clear();
    }

}
