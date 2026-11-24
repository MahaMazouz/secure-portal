package tn.epi.portal;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * Transforme les evenements d'authentification en metriques Prometheus :
 *   security_auth_attempts_total{result="success|failure", reason="..."}
 * Ces metriques alimentent les regles d'alerte (force brute) et les tests de detection.
 */
@Component
public class AuthenticationEventsListener {

    private final MeterRegistry registry;
    private final LoginAttemptService attempts;

    public AuthenticationEventsListener(MeterRegistry registry, LoginAttemptService attempts) {
        this.registry = registry;
        this.attempts = attempts;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        attempts.loginSucceeded(event.getAuthentication().getName());
        registry.counter("security.auth.attempts", "result", "success").increment();
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        attempts.loginFailed(event.getAuthentication().getName());
        registry.counter("security.auth.attempts", "result", "failure",
                "reason", event.getException().getClass().getSimpleName()).increment();
    }
}
