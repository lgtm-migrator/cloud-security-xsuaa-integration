package com.sap.cloud.security.samples.x509;

import com.sap.cloud.security.servlet.TokenAuthenticationResult;
import com.sap.cloud.security.token.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter("/*") // filter for any endpoint
public class IasSecurityFilter implements Filter {
    private static final Logger LOGGER = LoggerFactory.getLogger(IasSecurityFilter.class);
    private final ReuseServiceIasAuthenticator reuseServiceIasAuthenticator;

    public IasSecurityFilter() {
        reuseServiceIasAuthenticator = new ReuseServiceIasAuthenticator();
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            TokenAuthenticationResult authenticationResult = reuseServiceIasAuthenticator.validateRequest(request, response);
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            boolean x509Valid = reuseServiceIasAuthenticator.validateX509(httpRequest);
            if (authenticationResult.isAuthenticated() && x509Valid) {
                LOGGER.debug("AUTHENTICATED");
                chain.doFilter(request, response);
            } else {
                LOGGER.debug("UNAUTHENTICATED");
                sendUnauthenticatedResponse(response, authenticationResult.getUnauthenticatedReason());
            }
        } finally {
            SecurityContext.clearToken();
        }
    }

    private void sendUnauthenticatedResponse(ServletResponse response, String unauthenticatedReason) {
        if (response instanceof HttpServletResponse) {
            try {
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, unauthenticatedReason); // 401
            } catch (IOException e) {
                LOGGER.error("Failed to send error response", e);
            }
        }
    }

    @Override
    public void destroy() {
    }
}
