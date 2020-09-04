package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.test.RSAKeys;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import com.sap.xs2.security.container.UserInfo;
import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Performance test for java-container-security jwt token validation.
 */
public class UserInfoPerformanceIT {

	private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoPerformanceIT.class);

	@Rule
	public EnvironmentVariables environmentVariables = new EnvironmentVariables();

	@BeforeClass
	public static void setUp() {
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
	}

	@Test
	public void offlineValidation() throws Exception {
		String vcapServices = IOUtils.resourceToString("/xsuaa/vcap_services-single.json", StandardCharsets.UTF_8);
		environmentVariables.set("VCAP_SERVICES", vcapServices);

		String token = JwtGenerator.getInstanceFromFile(XSUAA, "/xsuaa/token.json")
				.withPrivateKey(RSAKeys.loadPrivateKey("/privateKey.txt"))
				.withClaimValue("client_id", "clientId")
				.withClaimValue("zid", "uaa")
				.createToken()
				.getTokenValue();

		UserInfo verifiedUserInfo = UserInfo.getVerifyUserInfo(token);
		assertThat(verifiedUserInfo).isNotNull();
		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> UserInfo.getVerifyUserInfo(token));
		LOGGER.info("Offline validation result: {}", result.toString());
	}

}

