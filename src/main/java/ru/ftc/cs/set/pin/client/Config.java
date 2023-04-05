package ru.ftc.cs.set.pin.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

//import static ru.ftc.cs.set.pin.client.Main.console;

public class Config {

    private final Properties props;

    public Config() throws IOException {
        String fileName = System.getProperty("config", "set-pin-client.conf");
        System.out.println( fileName);

        props = new Properties();
        try (InputStream fis = new FileInputStream(new File(fileName))) {
            props.load(fis);
        }
    }

    public String getBaseUrl() {
        return props.getProperty("base-url");
    }

    public String getHostHeader() {
        return props.getProperty("host-header");
    }

    public String getXCsOriginatorHeader() {
        return props.getProperty("x-cs-originator-header");
    }

    public String getXCsInstanceHeader() {
        return props.getProperty("x-cs-instance-header");
    }

    public String getSslClientCertHeader() {
        return props.getProperty("ssl-client-cert-header");
    }

    public String getSslClientCertHeaderHex() {
        return props.getProperty("ssl-client-cert-header-hex");
    }

    public String getKeystore() {
        return props.getProperty("keystore");
    }

    public String getKeystorePass() {
        return props.getProperty("keystore-pass");
    }

    public String getTruststore() {
        return props.getProperty("truststore");
    }

    public String getTruststorePass() {
        return props.getProperty("truststore-pass");
    }

    public String getConnectTimeoutMs() { return props.getProperty("connect-timeout-ms", "1000"); }

    public String getReadTimeoutMs() { return props.getProperty("read-timeout-ms", "10000"); }
}
