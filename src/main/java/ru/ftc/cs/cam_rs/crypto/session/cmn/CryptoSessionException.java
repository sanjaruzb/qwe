package ru.ftc.cs.cam_rs.crypto.session.cmn;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static java.lang.String.format;
import static java.util.Objects.isNull;

public class CryptoSessionException extends RuntimeException {

    public CryptoSessionException(String message) {
        super(message);
    }

    public CryptoSessionException(@Nonnull String message, @Nullable Throwable cause) {
        super(message, cause);
    }


    public static void checkNonNull(@Nonnull String objName, @Nullable Object obj) {
        if (isNull(obj)) {
            throw new CryptoSessionException(format("illegal session state, '%s' missing", objName));
        }
    }
}
