package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.mtls.SSLContextFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class HttpsClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpsClient.class);
    private final OAuth2ServiceConfiguration serviceConfiguration;

    public HttpsClient(OAuth2ServiceConfiguration serviceConfiguration) {
        this.serviceConfiguration = serviceConfiguration;
    }

    public CloseableHttpClient getHttpClient() throws ServiceClientException {

        String cert = serviceConfiguration.getProperty("certificate");
        String key = serviceConfiguration.getProperty("key");
        LOGGER.debug("Cert and key from Ias binding {}\n {}", cert, key);

        SSLContext sslContext;
        try {
            sslContext = SSLContextFactory.getInstance().create(cert, key);
        } catch (IOException | GeneralSecurityException e) {
            throw new ServiceClientException(String.format("Couldn't set up Https client for service provider. %s.%s", e.getMessage(), e));
        }

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);

        return HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLSocketFactory(socketFactory)
                .build();
    }
}
