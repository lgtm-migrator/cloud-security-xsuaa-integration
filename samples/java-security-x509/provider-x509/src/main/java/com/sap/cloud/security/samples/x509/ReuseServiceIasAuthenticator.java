package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticationResult;
import com.sap.cloud.security.servlet.TokenAuthenticatorResult;
import com.sap.cloud.security.token.SecurityContext;
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
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ReuseServiceIasAuthenticator extends IasTokenAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReuseServiceIasAuthenticator.class);
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

    @Override
    public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
        TokenAuthenticationResult result = super.validateRequest(request, response);
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (validateX509(httpRequest)) {
            return result;
        } else {
            return TokenAuthenticatorResult.createUnauthenticated("Invalid X509 certificate");
        }
    }

    boolean validateX509(HttpServletRequest httpRequest) {
        //TODO introduce cache as described here: https://github.wdf.sap.corp/CPSecurity/Knowledge-Base/blob/master/03_ApplicationSecurity/ProofOfPossession.md#cache
        JSONArray proofTokens = getProofToken();
        if (proofTokens == null) {
            return false;
        }
        X509Certificate x509Cert;
        try {
            x509Cert = decodeX509(httpRequest.getHeader("x-forwarded-client-cert"));
            LOGGER.debug("Incoming request x509 issuer DN: {}, issuer: {}", x509Cert.getIssuerDN().getName(), x509Cert.getSubjectDN().getName());

            for (Object proofToken : proofTokens) {
                JSONObject proofTokenObject = (JSONObject) proofToken;
                if (proofTokenObject.getString("providerClientId").equals(getServiceConfiguration().getClientId())) {
                    JSONArray x509List = proofTokenObject.getJSONArray("x509");
                    for (Object x509 : x509List) {
                        JSONObject x509Object = (JSONObject) x509;
                        String trustedDn = x509Object.getString("dn");
                        String trustedIssuer = x509Object.getString("issuer");
                        if (trustedIssuer.equals(x509Cert.getIssuerDN().getName().replaceAll(" *, *", ",")) &&
                                trustedDn.equals(x509Cert.getSubjectDN().getName().replaceAll(" *, *", ","))) {
                            LOGGER.info("x509 validation successful");
                            SecurityContext.setConsumedServiceId(proofTokenObject.getJSONArray("consumedServiceInstanceIds"));
                            return true;

                        }
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
    protected JSONArray getProofToken() {
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

    JSONArray decodeProofToken(String proofToken) {
        LOGGER.debug("Proof token value: {}", proofToken);
        return new JSONArray(proofToken);
    }

}
