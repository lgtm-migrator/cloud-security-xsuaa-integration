package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.extension.IasExtension;
import com.sap.cloud.security.test.extension.SecurityTestExtension;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith({IasExtension.class, SystemStubsExtension.class})
public class HelloJavaServletIntegrationTest {

    @SystemStub
    private static EnvironmentVariables environmentVariables;

    @BeforeAll
    static void beforeAll() throws IOException {
        String vcap = IOUtils.resourceToString("/vcap_x509.json", StandardCharsets.UTF_8);
        environmentVariables.set("VCAP_SERVICES", vcap);
    }

    @RegisterExtension
    public static SecurityTestExtension testExtension = IasExtension.forService(Service.IAS)
            .useApplicationServer()
            .addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT);

    @org.junit.jupiter.api.Test
    public void requestWithoutAuthorizationHeader_unauthenticated() throws IOException {
        HttpGet request = createGetRequest(null);
        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
        }
    }

    @org.junit.jupiter.api.Test
    public void requestWithEmptyAuthorizationHeader_unauthenticated() throws IOException {
        HttpGet request = createGetRequest("");
        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
        }
    }

    @org.junit.jupiter.api.Test
    public void request_withValidToken() throws IOException {

        Token token = testExtension.getContext().getPreconfiguredJwtGenerator()
                .withClaimValue(TokenClaims.EMAIL, "john.doe@email.com")
                .createToken();

        HttpGet request = createGetRequest(token.getTokenValue());
        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
            assertThat(responseBody).isEqualTo("You ('john.doe@email.com') can access provider service with x509");
        }
    }

    @Test
    public void request_withInvalidToken_unauthenticated() throws IOException {
        HttpGet request = createGetRequest(testExtension.getContext().getPreconfiguredJwtGenerator()
                .withClaimValue(TokenClaims.ISSUER, "INVALID Issuer")
                .createToken().getTokenValue());
        try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
            assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
        }
    }

    private HttpGet createGetRequest(String bearerToken) {
        HttpGet httpGet = new HttpGet(testExtension.getContext().getApplicationServerUri() + HelloJavaServlet.ENDPOINT);
        if (bearerToken != null) {
            httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        return httpGet;
    }
}