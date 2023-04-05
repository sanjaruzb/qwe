package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Base64;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

/**
 * <a href="https://tools.ietf.org/html/rfc7515#appendix-C">Base64url without padding</a>
 */
public class SecureB64u implements SecureObject {


    private final BytesRef bytesRef;

    private SecureB64u(@Nonnull BytesRef bytesRef) {
        this.bytesRef = bytesRef;
    }



    public static @Nonnull SecureB64u copy(@Nonnull SecureString secureString) {
        return copy(secureString.getCharsRef());
    }

    public static @Nonnull SecureB64u copy(@Nonnull CharsRef charsRef) {

        ByteBuffer iso88591ByteBuffer = ISO_8859_1.encode(charsRef.wrapToBuffer());

        ByteBuffer byteBuffer = Base64.getUrlDecoder().decode(iso88591ByteBuffer);

        // clear all ISO_8859_1 encoded bytes!
        BytesRef.wrap(iso88591ByteBuffer.array()).clear();

        return new SecureB64u(BytesRef.wrap(byteBuffer.array()));
    }

    public static @Nonnull SecureB64u wrap(@Nonnull BytesRef bytesRef) {
        return new SecureB64u(bytesRef);
    }



    public @Nonnull BytesRef getBytesRef() {
        return bytesRef;
    }

    public @Nonnull SecureString copyToString() {

        ByteBuffer iso88591ByteBuffer = Base64.getUrlEncoder()
                .withoutPadding()
                .encode(bytesRef.wrapToBuffer());

        CharBuffer charBuffer = ISO_8859_1.decode(iso88591ByteBuffer);

        // clear ISO_8859_1 encoded bytes!
        BytesRef.wrap(iso88591ByteBuffer.array()).clear();

        return SecureString.wrap(CharsRef.wrap(charBuffer.array()));
    }

    /**
     * Useful when encoded content is UTF-8 bytes of JSON.
     */
    public @Nonnull SecureJson copyToJson() {
        return SecureJson.copy(bytesRef);
    }



    /**
     * WARN: Use it only if you are sure that the content is not secret.
     */
    public @Nonnull String toInsecureString() {
        return copyToString().toInsecure();
    }



    @Override
    public void clear() {
        bytesRef.clear();
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecureB64u that = (SecureB64u) o;
        return Objects.equals(bytesRef, that.bytesRef);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytesRef);
    }
}
