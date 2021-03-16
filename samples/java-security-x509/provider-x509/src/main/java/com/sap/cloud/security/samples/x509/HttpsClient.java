package com.sap.cloud.security.samples.x509;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.SSLContext;

public class HttpsClient {

    private final SSLContext sslContext;

    public HttpsClient(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    public CloseableHttpClient getHttpClient() {

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);

        return HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLSocketFactory(socketFactory)
                .build();
    }
}
