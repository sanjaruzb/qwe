package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static java.util.Arrays.stream;

public class CharsRef implements SecureObject {

    private static final char ZERO_CHAR = (char) 0;


    private final char[] chars;
    private final int offset;
    private final int length;

    private CharsRef(@Nonnull char[] chars, int offset, int length) {
        checkBorders(0, chars.length, offset, length);

        this.chars = chars;
        this.offset = offset;
        this.length = length;
    }

    private static void checkBorders(int srcOffset, int srcLength, int dstOffset, int dstLength) {
        if (dstOffset < srcOffset) {
            throw new IllegalArgumentException("Invalid offset: " + dstOffset);
        }
        if (dstLength < 0 || (dstOffset + dstLength) > (srcOffset + srcLength)) {
            throw new IllegalArgumentException("Invalid length: " + dstLength);
        }
    }



    public static @Nonnull CharsRef wrap(@Nonnull char[] chars) {
        return CharsRef.wrap(chars, 0, chars.length);
    }

    public static @Nonnull CharsRef wrap(@Nonnull char[] chars, int offset, int length) {
        return new CharsRef(chars, offset, length);
    }

    public static @Nonnull CharsRef copy(@Nonnull CharsRef charsRef) {
        return copy(charsRef.getChars(), charsRef.getOffset(), charsRef.getLength());
    }

    public static @Nonnull CharsRef copy(@Nonnull char[] original) {
        return copy(original, 0, original.length);
    }

    public static @Nonnull CharsRef copy(@Nonnull char[] original, int offset, int length) {
        checkBorders(0, original.length, offset, length);

        char[] copy = new char[length];
        System.arraycopy(original, offset, copy, 0, length);

        return CharsRef.wrap(copy, 0, copy.length);
    }



    public @Nonnull char[] getChars() {
        return chars;
    }

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public CharBuffer wrapToBuffer() {
        return CharBuffer.wrap(chars, offset, length);
    }

    public @Nonnull CharsRef wrap(int offset, int length) {
        checkBorders(this.offset, this.length, offset, length);

        return CharsRef.wrap(this.chars, offset, length);
    }

    public @Nonnull CharsRef copy(int offset, int length) {
        checkBorders(this.offset, this.length, offset, length);

        return CharsRef.copy(this.chars, offset, length);
    }

    public @Nonnull CharsRef copy() {
        return CharsRef.copy(this.chars, offset, length);
    }



    public @Nonnull CharsRef copyConcat(@Nonnull CharsRef... refs) {
        int totalLength = length + stream(refs).mapToInt(arr -> arr.length).sum();

        CharBuffer charBuffer = CharBuffer.allocate(totalLength);

        charBuffer.put(chars, offset, length);

        for (CharsRef ref : refs) {
            charBuffer.put(ref.getChars(), ref.getOffset(), ref.getLength());
        }

        return CharsRef.wrap(charBuffer.array(), 0, charBuffer.limit());
    }



    public List<CharsRef> split(char ch) {
        List<CharsRef> result = new ArrayList<>();

        int prev = offset;
        for (int i = offset; i < (offset + length); ++i) {
            if (chars[i] == ch) {
                result.add(wrap(prev, i - prev));
                prev = i+1;
            }
        }
        result.add(wrap(prev, length - (prev - offset)));

        return result;
    }



    @Override
    public void clear() {
        Arrays.fill(chars, offset, offset + length, ZERO_CHAR);
    }

    public boolean isClear() {
        CharBuffer buffer = CharBuffer.wrap(chars, offset, length);
        char result = ZERO_CHAR;
        while (buffer.hasRemaining()) {
            result |= buffer.get();
        }
        return result == ZERO_CHAR;
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CharsRef charsRef = (CharsRef) o;
        return  chars  == charsRef.chars  && // compare references!
                offset == charsRef.offset &&
                length == charsRef.length;
    }

    @Override
    public int hashCode() {
        return Objects.hash(chars, offset, length);
    }
}
