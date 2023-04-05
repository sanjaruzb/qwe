package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;

public class SecureString implements SecureObject {


    private final CharsRef charsRef;

    private SecureString(@Nonnull CharsRef charsRef) {
        this.charsRef = charsRef;
    }



    public static @Nonnull SecureString copy(@Nonnull BytesRef utf8BytesRef) {

        CharBuffer charBuffer = UTF_8.decode(utf8BytesRef.wrapToBuffer());

        CharsRef charsRef = CharsRef.wrap(charBuffer.array(), 0, charBuffer.length());

        return new SecureString(charsRef);
    }

    public static @Nonnull SecureString wrap(@Nonnull CharsRef charsRef) {
        return new SecureString(charsRef);
    }

    /**
     * Use only for non-secret strings
     */
    public static @Nonnull SecureString copy(@Nonnull String str) {
        return SecureString.copy(BytesRef.wrap(str.getBytes(UTF_8)));
    }



    /**
     * Don't forget to clear the result
     */
    public @Nonnull BytesRef copyToBytesRef(@Nonnull Charset charset) {

        ByteBuffer byteBuffer = charset.encode(charsRef.wrapToBuffer());

        return BytesRef.wrap(byteBuffer.array(), 0, byteBuffer.remaining());
    }

    public @Nonnull CharsRef getCharsRef() {
        return charsRef;
    }



    /**
     * WARN: Use it only if you are sure that the content is not secret.
     */
    public @Nonnull String toInsecure() {
        // content is placed in heap without any possibility to be cleared!
        return new String(charsRef.getChars(), charsRef.getOffset(), charsRef.getLength());
    }



    public @Nonnull SecureString copy() {
        return SecureString.wrap(CharsRef.copy(charsRef));
    }


    public @Nonnull SecureString copyConcat(SecureString...strings) {

        CharsRef[] refs = new CharsRef[strings.length];

        for (int i = 0; i < strings.length; ++i) {
            refs[i] = strings[i].getCharsRef();
        }

        return SecureString.wrap(charsRef.copyConcat(refs));
    }



    public @Nonnull List<SecureString> split(char ch) {
        return charsRef.split(ch)
                .stream()
                .map(SecureString::wrap)
                .collect(toList());
    }



    @Override
    public void clear() {
        charsRef.clear();
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecureString that = (SecureString) o;
        return this.charsRef.wrapToBuffer().equals(that.charsRef.wrapToBuffer());
    }

    @Override
    public int hashCode() {
        int result = 1;
        for (int i = charsRef.getOffset(); i < (charsRef.getOffset() + charsRef.getLength()); ++i){
            result = 31 * result + i;
        }
        return result;
    }
}
