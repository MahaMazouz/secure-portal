package tn.epi.portal;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Verrouille un compte apres MAX_ATTEMPTS echecs en moins de 15 minutes.
 * Limite connue : en production, la Map serait remplacee par un cache borne
 * (sinon un attaquant peut envoyer des millions de noms d'utilisateur differents).
 */
@Component
public class LoginAttemptService {

    static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();
    private final Counter lockedCounter;

    public LoginAttemptService(MeterRegistry registry) {
        this.lockedCounter = Counter.builder("security.account.locked")
                .description("Comptes bloques apres trop d'echecs")
                .register(registry);
    }

    public void loginFailed(String username) {
        Deque<Instant> list = failures.computeIfAbsent(username, k -> new ConcurrentLinkedDeque<>());
        list.add(Instant.now());
        purge(list);
        if (list.size() == MAX_ATTEMPTS) {
            lockedCounter.increment();
        }
    }

    public void loginSucceeded(String username) {
        failures.remove(username);
    }

    public boolean isBlocked(String username) {
        Deque<Instant> list = failures.get(username);
        if (list == null) {
            return false;
        }
        purge(list);
        return list.size() >= MAX_ATTEMPTS;
    }

    private void purge(Deque<Instant> list) {
        Instant limit = Instant.now().minus(WINDOW);
        while (!list.isEmpty() && list.peekFirst().isBefore(limit)) {
            list.pollFirst();
        }
    }
}
