package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(HelloJavaServlet.ENDPOINT)
public class HelloJavaServlet extends HttpServlet {
    static final String ENDPOINT = "/hello-x509";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(HelloJavaServlet.class);

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        response.setContentType("text/plain");
        Token token = SecurityContext.getToken();

        try {
            response.getWriter().write("You ('"
                    + token.getClaimAsString(TokenClaims.EMAIL) + "') "
                    + "can access provider service with x509");
        } catch (final IOException e) {
            LOGGER.error("Failed to write error response: {}.", e.getMessage(), e);
        } catch (Exception exception) {
            LOGGER.error("Couldn't call reuse-service. {} ", exception.getMessage());
        }
    }

}
