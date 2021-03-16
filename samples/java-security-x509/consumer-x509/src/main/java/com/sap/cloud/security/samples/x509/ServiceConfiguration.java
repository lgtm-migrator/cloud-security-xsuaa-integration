package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServiceConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceConfiguration.class);

    protected JSONObject getReuseServiceConfiguration(String reuseServiceName) {
        String vcapServices = System.getenv(CFConstants.VCAP_SERVICES);
        LOGGER.debug("vcap-services {}", vcapServices);

        JSONArray reuseServiceList = new JSONObject(vcapServices).getJSONArray(reuseServiceName);
        JSONObject reuseService = (JSONObject) reuseServiceList.get(0);
        LOGGER.info("Reuse-service '{}' configuration {}", reuseServiceName, reuseService);

        return reuseService;
    }

    protected OAuth2ServiceConfiguration getIasServiceConfiguration() {
        OAuth2ServiceConfiguration config = Environments.getCurrent().getIasConfiguration();
        LOGGER.info("IAS service config: {}", config);
        if (config == null) {
            throw new IllegalStateException("There must be a service configuration.");
        }
        return config;
    }

}
