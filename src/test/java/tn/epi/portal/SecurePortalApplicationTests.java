package tn.epi.portal;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

// Les mots de passe n'existent pas pendant les tests : on les fournit ici
@SpringBootTest(properties = {"app.user.password=user-test-only", "app.admin.password=admin-test-only"})
class SecurePortalApplicationTests {

    @Test
    void contextLoads() {
        // verifie que l'application demarre
    }
}
