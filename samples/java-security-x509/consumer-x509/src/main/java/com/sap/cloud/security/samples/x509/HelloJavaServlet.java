package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Objects;

@WebServlet(HelloJavaServlet.ENDPOINT)
public class HelloJavaServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(HelloJavaServlet.class);

    static final String ENDPOINT = "/hello-x509";
    static final String HAPPY_FACE = "<span style='font-size:100px;'>&#128515;</span>";
    static final String SAD_FACE = "<span style='font-size:100px;'>&#128530;</span>";

    private static final long serialVersionUID = 1L;
    private final ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
    private final HttpsClient httpsClient = new HttpsClient(serviceConfiguration.getIasServiceConfiguration());

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        response.setContentType("text/plain");
        Token token = SecurityContext.getToken();
        String serviceUrl = serviceConfiguration.getReuseServiceConfiguration("provider-service-instance").getJSONObject("credentials").getString("url") + ENDPOINT;
        LOGGER.debug("reuse-service url: {}", serviceUrl);

        try {
            HttpUriRequest getRequest = new HttpGet(serviceUrl);
            getRequest.addHeader("Authorization", Objects.requireNonNull(token, "IAS Token cannot be null").getTokenValue());

            LOGGER.debug("IAS token value: {}", token.getTokenValue());
            HttpResponse reuseServiceResponse
                    = httpsClient.getHttpClient().execute(getRequest);

            String emoji = reuseServiceResponse.getStatusLine().getStatusCode() == 200 ? HAPPY_FACE : SAD_FACE;
            response.getWriter()
                    .write("<!DOCTYPE html><html><body><p>Your request was authenticated and forwarded to service provider." +
                    "</p><br><h2>Response from service provider</h2> " +
                    "<ul><li>Status code: " + reuseServiceResponse.getStatusLine().getStatusCode() + "</li>"
                    + emoji + "</ul></body></html>");
        } catch (ServiceClientException | UnknownHostException e) {
            try {
                response.getWriter().write("<!DOCTYPE html><html>" + SAD_FACE + "</html>");
            } catch (IOException ioException) {
                LOGGER.error("Failed to write error response: {}.", e.getMessage(), e);
            }
            LOGGER.error("Couldn't call service provider. {}. ", e.getMessage(), e);
        } catch (final IOException e) {
            LOGGER.error("Failed to write error response: {}.", e.getMessage(), e);
        }
    }

}
