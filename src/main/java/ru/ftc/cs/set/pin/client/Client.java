package ru.ftc.cs.set.pin.client;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import ru.ftc.cs.cam_rs.crypto.session.cmn.BytesRef;
import ru.ftc.cs.cam_rs.crypto.session.cmn.SecureJson;
import ru.ftc.cs.cam_rs.crypto.session.cmn.SecureString;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.nonNull;
//import static ru.ftc.cs.set.pin.client.Main.console;

public class Client {
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HOST_HEADER         = "Host";
    public static final String JSON                = "application/json";
    public static final String JOSE                = "application/jose";

    private static final String X_CS_ORIGINATOR   = "X-CS-Originator";
    private static final String X_CS_INSTANCE     = "X-CS-Instance";
    private static final String X_CS_REQUEST_ID   = "X-CS-RequestId";
    private static final String X_CS_REQUEST_TIME = "X-CS-RequestTime";
    private static final String SSL_CLIENT_CERT_H = "SSL_CLIENT_CERT";

    private final String baseUrl;

    private final String hostHeader;
    private final String sslClientCertHeader;
    private final String xCsOriginatorHeader;
    private final String xCsInstanceHeader;

    private final HttpClientBuilder clientBuilder;

    public Client(Config cfg) throws IOException, GeneralSecurityException, DecoderException {
        this.baseUrl = cfg.getBaseUrl();

        this.xCsInstanceHeader   = cfg.getXCsInstanceHeader();
        this.xCsOriginatorHeader = cfg.getXCsOriginatorHeader();

        this.hostHeader = cfg.getHostHeader();

        if (nonNull(cfg.getSslClientCertHeader())) {
            sslClientCertHeader = cfg.getSslClientCertHeader();
        } else {
            String sslCertHex = cfg.getSslClientCertHeaderHex();
            if (nonNull(sslCertHex)) {
                byte[] bCert = Hex.decodeHex(sslCertHex);
                sslClientCertHeader = Base64.encodeBase64String(bCert);
            } else {
                sslClientCertHeader = null;
            }
        }

        int connectTimeout = Integer.parseInt(cfg.getConnectTimeoutMs());
        int readTimeout = Integer.parseInt(cfg.getReadTimeoutMs());

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(-1)
                .setConnectTimeout(connectTimeout)
                .setSocketTimeout(readTimeout)
                .build();

        clientBuilder = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig);

        String keystore       = cfg.getKeystore();
        String keystorePass   = cfg.getKeystorePass();
        String truststore     = cfg.getTruststore();
        String truststorePass = cfg.getTruststorePass();

        if (nonNull(keystore)) {
            System.out.println( keystore);

            String keystoreType = keystore.endsWith(".pfx") || keystore.endsWith(".p12") ? "pkcs12" : "jks";
            KeyStore clientStore = loadKeyStore(keystoreType, keystore, keystorePass);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientStore, keystorePass.toCharArray());
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            TrustManager[] trustManagers;
            if (nonNull(truststore)) {
                KeyStore trustStore = loadKeyStore("jks", truststore, truststorePass);
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                trustManagers = trustManagerFactory.getTrustManagers();
            } else {
                trustManagers = null;
            }

            SSLContext sslCtx = SSLContext.getInstance("TLSv1.2");
            sslCtx.init(keyManagers, trustManagers, new SecureRandom());

            clientBuilder
                    .setSSLSocketFactory(new SSLConnectionSocketFactory(sslCtx, new NoopHostnameVerifier()))
                    .setSSLContext(sslCtx);
        }
    }


    public SecureJson sendCreatePinSession(SecureJson req) throws URISyntaxException, IOException {
        String uri = baseUrl + "/pin/session";
        System.out.println( uri);

        BytesRef br = req.getString().copyToBytesRef(UTF_8);

        HttpPost post = new HttpPost(new URI(uri));
        post.setEntity(new ByteArrayEntity(br.getBytes(), br.getOffset(), br.getLength()));
        post.setHeader(HEADER_CONTENT_TYPE, JSON);
        if (hostHeader != null) { post.setHeader(HOST_HEADER, hostHeader); }
        post.setHeader(X_CS_ORIGINATOR, xCsOriginatorHeader);
        if (xCsInstanceHeader != null) { post.setHeader(X_CS_INSTANCE, xCsInstanceHeader); }
        if (sslClientCertHeader != null) { post.setHeader(SSL_CLIENT_CERT_H, sslClientCertHeader); }
        post.setHeader(X_CS_REQUEST_ID,   generateRequestId());
        post.setHeader(X_CS_REQUEST_TIME, generateRequestTime());

        try (CloseableHttpResponse response = clientBuilder.build().execute(post)) {
            int responseStatusCode = response.getStatusLine().getStatusCode();

            System.out.println(responseStatusCode);

            if (responseStatusCode != 200) {
                System.out.println(EntityUtils.toString(response.getEntity()));
                throw new IllegalStateException(
                        String.format("wrong response code on create pin session: respCode=[%d]", responseStatusCode));
            }

            byte[] responseText = nonNull(response.getEntity()) ? EntityUtils.toByteArray(response.getEntity()) : null;
            if (responseText == null) {
                throw new IllegalStateException("no response body on create-pin-session");
            }

            return SecureJson.copy(BytesRef.wrap(responseText));
        } finally {
            br.clear();
        }
    }

    public void sendSetPin(SecureString sessionId, SecureString jweBody) throws URISyntaxException, IOException {
        // acpt and sessionId - non critical info
        // additionally - unable to avoid creating string during creating URI
        String uri = baseUrl + "/pin/session/" + sessionId.toInsecure();
        System.out.println( uri);

        BytesRef br = jweBody.copyToBytesRef(UTF_8);

        HttpPut put = new HttpPut(new URI(uri));
        put.setEntity(new ByteArrayEntity(br.getBytes(), br.getOffset(), br.getLength()));
        put.setHeader(HEADER_CONTENT_TYPE, JOSE);
        if (hostHeader != null) { put.setHeader(HOST_HEADER, hostHeader); }
        put.setHeader(X_CS_ORIGINATOR, xCsOriginatorHeader);
        if (xCsInstanceHeader != null) { put.setHeader(X_CS_INSTANCE, xCsInstanceHeader); }
        if (sslClientCertHeader != null) { put.setHeader(SSL_CLIENT_CERT_H, sslClientCertHeader); }
        put.setHeader(X_CS_REQUEST_ID,   generateRequestId());
        put.setHeader(X_CS_REQUEST_TIME, generateRequestTime());

        try (CloseableHttpResponse response = clientBuilder.build().execute(put)) {
            int responseStatusCode = response.getStatusLine().getStatusCode();
            String responseText = nonNull(response.getEntity()) ? EntityUtils.toString(response.getEntity(), UTF_8) : null;

            System.out.println( responseStatusCode);
            System.out.println( responseText);

            if (responseStatusCode != 200) {
                throw new IllegalStateException(
                        String.format("wrong response code on set pin: respCode=[%d]", responseStatusCode));
            }
        } finally {
            br.clear();
        }
    }

    private String generateRequestId() {
        return String.valueOf(System.currentTimeMillis());
    }

    private String generateRequestTime() {
        return DateTimeFormatter.ofPattern("yyyyMMddHHmmss").format(Instant.now().atZone(ZoneOffset.UTC));
    }


    private static @Nonnull KeyStore loadKeyStore(@Nonnull String type,
                                                  @Nonnull String path,
                                                  @Nullable String pass) throws IOException, GeneralSecurityException {
        try (InputStream is = new FileInputStream(path)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(is, nonNull(pass) ? pass.toCharArray() : null);
            return keyStore;
        }
    }
}
