package tn.epi.portal;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.List;
import java.util.Map;

@RestController
public class ApiController {

    // Page d'accueil HTML avec des liens : le robot de ZAP (spider) decouvre ainsi les pages a tester
    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home() {
        return "<html><body><h1>Portail securise EPI</h1><ul>"
             + "<li><a href='/api/me'>Mon compte</a></li>"
             + "<li><a href='/api/items'>Articles</a></li>"
             + "<li><a href='/api/search?q=badge'>Recherche</a></li>"
             + "<li><a href='/api/admin/stats'>Administration</a></li>"
             + "</ul></body></html>";
    }

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of("user", auth.getName(),
                "roles", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    @GetMapping("/api/items")
    public List<Map<String, Object>> items() {
        return List.of(Map.of("id", 1, "name", "Badge"), Map.of("id", 2, "name", "Casque"));
    }

    // Recherche : le parametre est ENCODE avant d'etre renvoye (protection XSS).
    // La demo de la phase 7 retire volontairement HtmlUtils.htmlEscape sur la branche demo/xss.
    @GetMapping(value = "/api/search", produces = MediaType.TEXT_HTML_VALUE)
    public String search(@RequestParam String q) {
        return "<p>Resultats pour : " + HtmlUtils.htmlEscape(q) + "</p>";
    }

    @GetMapping("/api/admin/stats")
    public Map<String, Object> stats() {
        return Map.of("users", 2);
    }
}
