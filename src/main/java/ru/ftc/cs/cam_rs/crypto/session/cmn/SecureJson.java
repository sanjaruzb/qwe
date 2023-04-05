package ru.ftc.cs.cam_rs.crypto.session.cmn;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.CharBuffer;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

public class SecureJson implements SecureObject {

    private static final MappingJsonFactory factory = new MappingJsonFactory();


    private final Map<String, Object> map; // all string values are converted to SecureString
    private final SecureString secureString;

    private SecureJson(@Nonnull Map<String, Object> map, @Nonnull SecureString secureString) {
        this.map = map;
        this.secureString = secureString;
    }



    public @Nonnull SecureJson copy() {
        try (BytesRef utf8Bytes = secureString.copyToBytesRef(UTF_8)) {

            Map<String, Object> copiedMap = parseToMap(utf8Bytes, true);

            SecureString copiedString = secureString.copy();

            return new SecureJson(copiedMap, copiedString);

        } catch (IOException e) {
            throw new CryptoSessionException("failed to copy json", e);
        }
    }



    public static @Nonnull SecureJson copy(@Nonnull Object... kv) {
        if (kv.length == 0) {
            return copy(emptyMap());
        }
        if (kv.length % 2 != 0) {
            throw new IllegalArgumentException("Number of parameters must be even");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i +=2 ) {
            map.put((String) kv[i], kv[i+1]);
        }
        return copy(map);
    }

    /**
     * The map will be deep-copied.
     */
    public static SecureJson copy(@Nonnull Map<String, Object> map) {
        try {
            BytesRef utf8BytesRef = writeToUtf8Bytes(map);

            SecureString secureString = SecureString.copy(utf8BytesRef);

            Map<String, Object> copiedMap = parseToMap(utf8BytesRef, true);

            return new SecureJson(copiedMap, secureString);

        } catch (IOException e) {
            throw new CryptoSessionException("failed to generate json from map", e);
        }
    }



    private static @Nonnull BytesRef writeToUtf8Bytes(@Nonnull Map<String, Object> map) throws IOException {
        try (Generator generator = new Generator(map)) {
            return generator.write();
        }
    }



    private static class Generator implements Closeable {

        private final JsonGenerator jsonGenerator;
        private final SecureOutputStream outputStream;
        private final Map<String, Object> map;

        public Generator(@Nonnull Map<String, Object> map) throws IOException {
            this.outputStream = new SecureOutputStream();
            this.jsonGenerator = factory.createGenerator(outputStream, JsonEncoding.UTF8);
            this.map = map;
        }


        @Override
        public void close() throws IOException {
            jsonGenerator.close();
        }


        private @Nonnull BytesRef write() throws IOException {

            writeMap(map);

            jsonGenerator.flush();

            return outputStream.wrapToBytesRef();
        }


        private void writeMap(@Nonnull Map<String, Object> map) throws IOException {
            jsonGenerator.writeStartObject();

            for (Map.Entry<String, Object> entry : map.entrySet()) {
                jsonGenerator.writeFieldName(entry.getKey());
                writeValue(entry.getValue());
            }

            jsonGenerator.writeEndObject();
        }

        private void writeArray(@Nonnull Iterable<?> iterable) throws IOException {
            jsonGenerator.writeStartArray();

            for (Object value : iterable) {
                writeValue(value);
            }

            jsonGenerator.writeEndArray();
        }

        private void writeValue(@Nullable Object value) throws IOException {

            if (value instanceof SecureString) {
                CharBuffer charBuffer = ((SecureString) value).getCharsRef().wrapToBuffer();
                jsonGenerator.writeString(charBuffer.array(), charBuffer.arrayOffset(), charBuffer.length());

            } else if (value instanceof SecureB64u) {
                CharBuffer charBuffer = ((SecureB64u) value).copyToString().getCharsRef().wrapToBuffer();
                jsonGenerator.writeString(charBuffer.array(), charBuffer.arrayOffset(), charBuffer.length());

            } else if (value instanceof String) {
                jsonGenerator.writeString((String) value);

            } else if (value instanceof Map) {
                //noinspection unchecked
                writeMap((Map<String, Object>) value);

            } else if (isNull(value)) {
                jsonGenerator.writeNull();

            } else if (value instanceof Number) {
                writeNumber((Number) value);

            } else if (value instanceof Boolean) {
                jsonGenerator.writeBoolean((Boolean) value);

            } else if (value instanceof Object[]) {
                writeArray(asList((Object[]) value));

            } else if (value instanceof int[]) {
                int[] integers = (int[]) value;
                jsonGenerator.writeArray(integers, 0, integers.length);

            } else if (value instanceof long[]) {
                long[] longs = (long[]) value;
                jsonGenerator.writeArray(longs, 0, longs.length);

            } else if (value instanceof double[]) {
                double[] doubles = (double[]) value;
                jsonGenerator.writeArray(doubles, 0, doubles.length);

            } else {
                throw new IllegalArgumentException("Unsupported type: " + value.getClass());
            }
        }

        private void writeNumber(@Nonnull Number value) throws IOException {

            if (value instanceof Short) {
                jsonGenerator.writeNumber((Short) value);

            } else if (value instanceof Long) {
                jsonGenerator.writeNumber((Long) value);

            } else if (value instanceof BigInteger) {
                jsonGenerator.writeNumber((BigInteger) value);

            } else if (value instanceof Double) {
                jsonGenerator.writeNumber((Double) value);

            } else if (value instanceof Float) {
                jsonGenerator.writeNumber((Float) value);

            } else if (value instanceof BigDecimal) {
                jsonGenerator.writeNumber((BigDecimal) value);

            } else if (value instanceof Integer) {
                jsonGenerator.writeNumber((Integer) value);
            }
        }


        /**
         * Secure version of {@link ByteArrayOutputStream}.
         * Clears old buffer after grow.
         */
        private static class SecureOutputStream extends OutputStream {

            private byte[] buf;
            private int count;


            public SecureOutputStream() {
                this(512);
            }

            public SecureOutputStream(int initialSize) {
                if (initialSize < 0) {
                    throw new IllegalArgumentException("Negative initial size: " + initialSize);
                }

                this.buf = new byte[initialSize];
                this.count = 0;
            }



            public @Nonnull BytesRef wrapToBytesRef() {
                return BytesRef.wrap(buf, 0, count);
            }



            @Override
            public synchronized void write(int b) {
                ensureCapacity(count + 1);
                buf[count] = (byte) b;
                ++count;
            }

            @Override
            public synchronized void write(@Nonnull byte[] b, int off, int len) {
                if ((off < 0) || (off > b.length) || (len < 0) ||
                        ((off + len) - b.length > 0)) {
                    throw new IndexOutOfBoundsException();
                }
                ensureCapacity(count + len);
                System.arraycopy(b, off, buf, count, len);
                count += len;
            }

            private void ensureCapacity(int minCapacity) {
                if (minCapacity - buf.length > 0) {
                    grow(minCapacity);
                }
            }

            private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

            private void grow(int minCapacity) {

                int newCapacity = buf.length << 1;

                if (newCapacity - minCapacity < 0) {
                    newCapacity = minCapacity;
                }

                if (newCapacity - MAX_ARRAY_SIZE > 0) {
                    throw new OutOfMemoryError();
                }

                byte[] oldBuf = buf;

                buf = Arrays.copyOf(oldBuf, newCapacity);

                // clear old buffer!
                BytesRef.wrap(oldBuf).clear();
            }
        }
    }



    /**
     * @throws IllegalArgumentException if parsing failed
     */
    public static SecureJson copy(@Nonnull BytesRef utf8BytesRef) {
        try {
            Map<String, Object> map = parseToMap(utf8BytesRef, true);

            SecureString secureString = SecureString.copy(utf8BytesRef);

            return new SecureJson(map, secureString);

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JSON", e);
        }
    }



    private static @Nonnull Map<String, Object> parseToMap(@Nonnull BytesRef utf8BytesRef,
                                                           boolean useSecureStrings) throws IOException {
        try (Parser parser = new Parser(utf8BytesRef, useSecureStrings)) {
            return parser.parse();
        }
    }



    private static class Parser implements Closeable {


        private final JsonParser jsonParser;
        private final Set<CharsRef> jsonParserBufferRefs;
        private final boolean useSecureStrings;

        public Parser(@Nonnull BytesRef utf8BytesRef, boolean useSecureStrings) throws IOException {
            // UTF-8 will be automatically detected
            this.jsonParser = factory.createParser(utf8BytesRef.getBytes(), utf8BytesRef.getOffset(), utf8BytesRef.getLength());
            this.jsonParserBufferRefs = new HashSet<>();
            this.useSecureStrings = useSecureStrings;
        }



        public @Nonnull Map<String, Object> parse() throws IOException {
            try {
                jsonParser.nextToken();
                return parseObject();
            } finally {
                // now we can clear buffers of jackson
                jsonParserBufferRefs.forEach(CharsRef::clear);
            }
        }

        @Override
        public void close() throws IOException {
            this.jsonParser.close();
        }



        public @Nonnull Map<String, Object> parseObject() throws IOException {

            Map<String, Object> result = new HashMap<>();

            if (jsonParser.currentToken() != JsonToken.START_OBJECT) {
                throw new IllegalStateException("Unexpected current token: " + jsonParser.currentToken());
            }

            JsonToken token;
            String fieldName = "unknown";
            while (nonNull(token = jsonParser.nextToken()) && token != JsonToken.END_OBJECT) {
                if (token == JsonToken.FIELD_NAME) {
                    fieldName = jsonParser.currentName();
                } else {
                    result.put(fieldName, toValue(token));
                }
            }

            return result;
        }

        private @Nullable Object toValue(@Nonnull JsonToken token) throws IOException {

            Object result;

            if (token == JsonToken.VALUE_STRING) {
                if (useSecureStrings) {

                    CharsRef bufferRef = CharsRef.wrap(
                            jsonParser.getTextCharacters(),
                            jsonParser.getTextOffset(),
                            jsonParser.getTextLength());

                    // it is forbidden to clear jackson buffer right now,
                    // so we add reference to set to clear later
                    jsonParserBufferRefs.add(bufferRef);

                    result = SecureString.wrap(CharsRef.copy(bufferRef));

                } else {
                    result = jsonParser.getText();
                }

            } else if (token == JsonToken.START_OBJECT) {
                result = parseObject();

            } else if (token == JsonToken.VALUE_NULL) {
                result = null;

            } else if (token == JsonToken.VALUE_NUMBER_INT) {
                result = jsonParser.getLongValue();

            } else if (token == JsonToken.VALUE_NUMBER_FLOAT) {
                result = jsonParser.getDoubleValue();

            } else if (token == JsonToken.VALUE_TRUE) {
                result = true;

            } else if (token == JsonToken.VALUE_FALSE) {
                result = false;

            } else if (token == JsonToken.START_ARRAY) {
                JsonToken arrToken;
                List<Object> list = new ArrayList<>();
                while (nonNull(arrToken = jsonParser.nextToken()) && arrToken != JsonToken.END_ARRAY) {
                    list.add(toValue(arrToken));
                }
                result = list;

            } else {
                throw new IllegalArgumentException("Unsupported JSON token: " + token);
            }

            return result;
        }

    }



    @Override
    public void clear() {
        secureString.clear();
        map.forEach((s, o) -> {
            if (o instanceof SecureObject) {
                ((SecureObject) o).clear();
            }
        });
    }



    public @Nonnull SecureString getString() {
        return secureString;
    }

    public @Nonnull Map<String, Object> getMap() {
        return unmodifiableMap(map);
    }

    /**
     * WARN: Use it only if you are sure that the content is not secret.
     */
    @SuppressWarnings("unused")
    public @Nonnull String toInsecureString() {
        return secureString.toInsecure();
    }

    /**
     * WARN: Use it only if you are sure that the content is not secret.
     */
    public @Nonnull Map<String, Object> toInsecureMap() {
        try {
            BytesRef utf8BytesRef = writeToUtf8Bytes(map);

            return parseToMap(utf8BytesRef, false);

        } catch (IOException e) {
            throw new CryptoSessionException("Failed to expose JSON", e);
        }
    }



    /**
     * Useful when JSON must be converted to Base64Url of UTF-8 bytes.
     */
    public @Nonnull SecureB64u copyToB64u() {
        return SecureB64u.wrap(secureString.copyToBytesRef(UTF_8));
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecureJson that = (SecureJson) o;
        return Objects.equals(secureString, that.secureString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(secureString);
    }
}
