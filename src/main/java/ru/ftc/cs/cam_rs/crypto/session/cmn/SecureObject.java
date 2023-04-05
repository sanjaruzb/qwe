package ru.ftc.cs.cam_rs.crypto.session.cmn;

public interface SecureObject extends AutoCloseable {

    @Override
    default void close() {
        clear();
    }

    /**
     * Clears internal state objects.
     * So if internal object is instance of {@link SecureObject} it must be cleared too.
     */
    void clear();

}
