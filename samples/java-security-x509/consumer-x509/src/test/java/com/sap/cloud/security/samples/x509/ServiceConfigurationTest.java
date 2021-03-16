package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@ExtendWith(SystemStubsExtension.class)
class ServiceConfigurationTest {

    @SystemStub
    private static EnvironmentVariables environmentVariables;

    @BeforeAll
    static void beforeAll() throws IOException {
        String vcap = IOUtils.resourceToString("/vcap_x509.json", StandardCharsets.UTF_8);
        environmentVariables.set("VCAP_SERVICES", vcap);
    }

    @Test
    void serviceProviderConfigTest() {
        JSONObject serviceConfiguration = new ServiceConfiguration().getReuseServiceConfiguration("provider-service-instance");
        Assertions.assertNotNull(serviceConfiguration.get("credentials"));
        Assertions.assertEquals("https://my-reuse-service.url.com", serviceConfiguration.getJSONObject("credentials").getString("url"));

    }

    @Test
    void iasServiceConfigTest() {
        OAuth2ServiceConfiguration serviceConfiguration = new ServiceConfiguration().getIasServiceConfiguration();
        Assertions.assertNotNull(serviceConfiguration.getProperty("certificate"));
        Assertions.assertNotNull(serviceConfiguration.getProperty("key"));
    }
}