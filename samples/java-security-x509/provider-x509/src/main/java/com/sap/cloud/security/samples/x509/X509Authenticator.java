package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.xsuaa.mtls.SSLContextFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class X509Authenticator extends IasTokenAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509Authenticator.class);
    private HttpsClient httpsClient;

    @Override
    protected OAuth2ServiceConfiguration getServiceConfiguration() {
        OAuth2ServiceConfiguration config = serviceConfiguration != null ? serviceConfiguration
                : Environments.getCurrent().getIasConfiguration();
        if (config == null) {
            throw new IllegalStateException("There must be a service configuration.");
        }
        return config;
    }

    boolean validateX509(HttpServletRequest httpRequest) {
        Collections.list(httpRequest.getHeaderNames()).forEach(h -> LOGGER.debug("Headers: {}", h));
        JSONObject proofToken = getProofToken();
        X509Certificate x509Cert;
        try {
            x509Cert = decodeX509(httpRequest.getHeader("x-forwarded-client-cert"));
            LOGGER.debug("Incoming request x509 issuer DN: {}, issuer: {}", x509Cert.getIssuerDN().getName(), x509Cert.getSubjectDN().getName());

            if (proofToken != null) {
                JSONArray trustedX509List = proofToken.getJSONArray("x509");
                for (Object obj : trustedX509List) {
                    JSONObject trustedX509 = (JSONObject) obj;
                    String trustedDn = trustedX509.getString("dn");
                    String trustedIssuer = trustedX509.getString("issuer");
                    if (trustedIssuer.equals(x509Cert.getIssuerDN().getName().replaceAll(" *, *", ",")) &&
                            trustedDn.equals(x509Cert.getSubjectDN().getName().replaceAll(" *, *", ","))) {
                        LOGGER.info("x509 validation successful");
                        return true;

                    }
                }
            }
        } catch (CertificateException e) {
            LOGGER.error("X509 client certificate creation failed");
        }
        return false;
    }

    /**
     * Expects certificate header to contain only the last certificate in the chain
     *
     * @param pemEncodedX509 PEM encoded certificate
     * @return decoded X509 certificate
     * @throws CertificateException exception
     */
    X509Certificate decodeX509(String pemEncodedX509) throws CertificateException {
        if (pemEncodedX509 == null) {
            throw new CertificateException("Certificate header is missing");
        }

        if (!pemEncodedX509.startsWith("-----BEGIN CERTIFICATE-----") && !pemEncodedX509.endsWith("-----END CERTIFICATE-----")) {
            pemEncodedX509 = "-----BEGIN CERTIFICATE-----\n" + pemEncodedX509 + "\n-----END CERTIFICATE-----";
        }
        LOGGER.debug("PEM encoded certificate: {}", pemEncodedX509);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bytes = new ByteArrayInputStream(pemEncodedX509.getBytes());

        return (X509Certificate) certFactory.generateCertificate(bytes);
    }

    @Nullable
    protected JSONObject getProofToken() {
        try {
            this.httpsClient = new HttpsClient(SSLContextFactory.getInstance()
                    .create(getServiceConfiguration().getProperty("cert"), getServiceConfiguration().getProperty("key")));
        } catch (GeneralSecurityException | IOException e) {
            LOGGER.error("Couldn't initialize https client");
        }
        String proofTokenUrl = getServiceConfiguration().getProperty("prooftoken_url");
        LOGGER.info("proofToken URL: {}", proofTokenUrl);

        HttpUriRequest getRequest = new HttpGet(proofTokenUrl);
        HttpResponse proofTokenResponse;

        try {
            proofTokenResponse = httpsClient.getHttpClient().execute(getRequest);
            HttpEntity entity = proofTokenResponse.getEntity();
            String result = EntityUtils.toString(entity);
            return decodeProofToken(result);
        } catch (Exception exception) {
            LOGGER.error("X509 certificate validation failed, couldn't get Proof token {}", exception.getMessage());
            return null;
        }
    }

    JSONObject decodeProofToken(String proofToken) {
        String trimmed = proofToken.substring(1, proofToken.length() - 1);
        LOGGER.info("Proof token value: {}", trimmed);
        return new JSONObject(trimmed);
    }

}
