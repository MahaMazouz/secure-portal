package tn.epi.portal;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"app.user.password=user-test-only", "app.admin.password=admin-test-only"})
@AutoConfigureMockMvc
@AutoConfigureObservability   // sans elle, /actuator/prometheus est desactive pendant les tests
class SecurityTest {

    @Autowired
    MockMvc mvc;

    @Test
    void homeIsPublic() throws Exception {
        mvc.perform(get("/")).andExpect(status().isOk());
    }

    @Test
    void anonymousIsRejected() throws Exception {
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void validUserIsAccepted() throws Exception {
        mvc.perform(get("/api/me").with(httpBasic("alice", "user-test-only")))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("alice")));
    }

    @Test
    void userCannotReachAdmin() throws Exception {
        mvc.perform(get("/api/admin/stats").with(httpBasic("alice", "user-test-only")))
           .andExpect(status().isForbidden());
    }

    @Test
    void searchEscapesHtml() throws Exception {
        mvc.perform(get("/api/search").param("q", "<script>alert(1)</script>")
                .with(httpBasic("alice", "user-test-only")))
           .andExpect(content().string(containsString("&lt;script&gt;")));
    }

    @Test
    void securityHeadersArePresent() throws Exception {
        mvc.perform(get("/"))
           .andExpect(header().string("X-Content-Type-Options", "nosniff"))
           .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")));
    }

    @Test
    void prometheusEndpointExposesSecurityMetrics() throws Exception {
        mvc.perform(get("/api/me").with(httpBasic("alice", "faux")))
           .andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/prometheus"))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("security_auth_attempts_total")));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void accountIsLockedAfterFiveFailures() throws Exception {
        for (int i = 0; i < LoginAttemptService.MAX_ATTEMPTS; i++) {
            mvc.perform(get("/api/me").with(httpBasic("admin", "mauvais")))
               .andExpect(status().isUnauthorized());
        }
        // meme le bon mot de passe est refuse : le compte est bloque
        mvc.perform(get("/api/me").with(httpBasic("admin", "admin-test-only")))
           .andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/prometheus"))
           .andExpect(content().string(containsString("security_account_locked_total")));
    }
}
