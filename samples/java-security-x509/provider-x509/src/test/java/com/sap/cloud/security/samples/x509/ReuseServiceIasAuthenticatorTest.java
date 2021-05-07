package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.token.SecurityContext;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SystemStubsExtension.class)
class ReuseServiceIasAuthenticatorTest {

    @SystemStub
    private static EnvironmentVariables environmentVariables;

    private static final ReuseServiceIasAuthenticator REUSE_SERVICE_AUTHENTICATOR = mock(ReuseServiceIasAuthenticator.class);
    private static final String ISSUER = "CN=SAP Cloud Platform Client CA, OU=SAP Cloud Platform Clients, O=SAP SE, L=EU10-Canary, C=DE";
    private static final String DN = "CN=bdcd300c-b202-4a7a-bb95-2a7e6d15fe47/5ae493c5-e0ed-4d34-a1c6-97a7c715dc54, L=aoxk2addh.accounts400.ondemand.com, OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84, OU=Canary, OU=SAP Cloud Platform Clients, O=SAP SE, C=DE";

    private static HttpServletRequest servletRequestMock;
    private static String proofToken;
    private static String encodedRandomX509;
    private static String encodedSapX509;

    @BeforeAll
    static void beforeAll() throws IOException {
        String vcap = IOUtils.resourceToString("/vcap_x509.json", StandardCharsets.UTF_8);
        environmentVariables.set("VCAP_SERVICES", vcap);
        proofToken = IOUtils.resourceToString("/proof_token.json", StandardCharsets.UTF_8);
        encodedRandomX509 = IOUtils.resourceToString("/random_x509_pem.txt", StandardCharsets.UTF_8);
        encodedSapX509 = IOUtils.resourceToString("/sap_x509_pem.txt", StandardCharsets.UTF_8);
        servletRequestMock = mock(HttpServletRequest.class);
        when(servletRequestMock.getHeader("x-forwarded-client-cert")).thenReturn(encodedSapX509);
        when(servletRequestMock.getHeaderNames()).thenReturn(Collections.emptyEnumeration());
        when(REUSE_SERVICE_AUTHENTICATOR.getServiceConfiguration()).thenCallRealMethod();
    }

    @Test
    void decodeX509WithLabel() throws CertificateException {
        when(REUSE_SERVICE_AUTHENTICATOR.decodeX509(encodedSapX509)).thenCallRealMethod();
        X509Certificate cert = REUSE_SERVICE_AUTHENTICATOR.decodeX509(encodedSapX509);
        assertEquals(ISSUER, cert.getIssuerDN().toString());
        assertEquals(DN, cert.getSubjectDN().getName());
    }

    @Test
    void decodeX509WithoutLabel() throws CertificateException {
        when(REUSE_SERVICE_AUTHENTICATOR.decodeX509(encodedSapX509)).thenCallRealMethod();
        X509Certificate cert = REUSE_SERVICE_AUTHENTICATOR.decodeX509(encodedSapX509);
        assertEquals(ISSUER, cert.getIssuerDN().toString());
        assertEquals(DN, cert.getSubjectDN().getName());
    }

    @Test
    void decodeProofToken() {
        when(REUSE_SERVICE_AUTHENTICATOR.decodeProofToken(proofToken)).thenCallRealMethod();
        JSONObject proofTokenObj = (JSONObject) REUSE_SERVICE_AUTHENTICATOR.decodeProofToken(proofToken).get(0);
        JSONObject x509 = (JSONObject)  proofTokenObj.getJSONArray("x509").get(1);
        assertEquals(ISSUER.replaceAll(" *, *", ","), x509.getString("issuer"));
        assertEquals(DN.replaceAll(" *, *", ","), x509.getString("dn"));
    }

    @Test
    void validateX509() throws CertificateException {
        when(REUSE_SERVICE_AUTHENTICATOR.decodeProofToken(proofToken)).thenCallRealMethod();
        JSONArray proofTokenList = REUSE_SERVICE_AUTHENTICATOR.decodeProofToken(proofToken);
        when(REUSE_SERVICE_AUTHENTICATOR.getProofToken()).thenReturn(proofTokenList);
        when(REUSE_SERVICE_AUTHENTICATOR.decodeX509(encodedSapX509)).thenCallRealMethod();
        when(REUSE_SERVICE_AUTHENTICATOR.validateX509(servletRequestMock)).thenCallRealMethod();

        assertTrue(REUSE_SERVICE_AUTHENTICATOR.validateX509(servletRequestMock));
        assertNotNull(SecurityContext.getConsumedServiceIds());

        when(servletRequestMock.getHeader("x-forwarded-client-cert")).thenReturn(encodedRandomX509);
        when(REUSE_SERVICE_AUTHENTICATOR.decodeX509(encodedRandomX509)).thenCallRealMethod();
        assertFalse(REUSE_SERVICE_AUTHENTICATOR.validateX509(servletRequestMock));
    }

}