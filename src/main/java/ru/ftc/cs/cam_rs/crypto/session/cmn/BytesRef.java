package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;

import static java.util.Arrays.stream;

public class BytesRef implements SecureObject {

    private static final byte ZERO_BYTE = (byte) 0;


    private final byte[] bytes;
    private final int offset;
    private final int length;

    private BytesRef(@Nonnull byte[] bytes, int offset, int length) {
        checkBorders(0, bytes.length, offset, length);

        this.bytes = bytes;
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



    public static @Nonnull BytesRef wrap(@Nonnull byte[] bytes) {
        return BytesRef.wrap(bytes, 0, bytes.length);
    }

    public static @Nonnull BytesRef wrap(@Nonnull byte[] bytes, int offset, int length) {
        return new BytesRef(bytes, offset, length);
    }



    public @Nonnull byte[] getBytes() {
        return bytes;
    }

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public ByteBuffer wrapToBuffer() {
        return ByteBuffer.wrap(bytes, offset, length);
    }

    public @Nonnull BytesRef wrap(int offset, int length) {
        checkBorders(this.offset, this.length, offset, length);

        return BytesRef.wrap(this.bytes, offset, length);
    }


    @Override
    public void clear() {
        Arrays.fill(bytes, offset, offset + length, ZERO_BYTE);
    }

    public boolean isClear() {
        LongBuffer buffer = ByteBuffer.wrap(bytes, offset, length).asLongBuffer();
        long result = 0;
        while (buffer.hasRemaining()) {
            result |= buffer.get();
        }
        return result == 0;
    }



    private static final Random random = new SecureRandom();

    public @Nonnull BytesRef randomize() {

        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);

        System.arraycopy(randomBytes, 0, bytes, offset, length);

        // clear generated bytes
        BytesRef.wrap(randomBytes).clear();

        return this;
    }



    public @Nonnull BytesRef copy() {
        return BytesRef.wrap(ByteBuffer.allocate(length).put(wrapToBuffer()).array());
    }

    public @Nonnull BytesRef copyConcat(@Nonnull BytesRef... refs) {
        int totalLength = length + stream(refs).mapToInt(arr -> arr.length).sum();

        ByteBuffer byteBuffer = ByteBuffer.allocate(totalLength);

        byteBuffer.put(bytes, offset, length);

        for (BytesRef ref : refs) {
            byteBuffer.put(ref.getBytes(), ref.getOffset(), ref.getLength());
        }

        return BytesRef.wrap(byteBuffer.array(), 0, totalLength);
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BytesRef bytesRef = (BytesRef) o;
        return  bytes  == bytesRef.bytes  && // compare references!
                offset == bytesRef.offset &&
                length == bytesRef.length;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytes, offset, length);
    }
}
