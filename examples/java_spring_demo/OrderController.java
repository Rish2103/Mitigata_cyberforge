package com.cyberforge.demo;

import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Arrays;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

@RestController
@RequestMapping("/api/java")
public class OrderController {

    // 1. Hardcoded API Secret (CWE-798 -> Code only)
    private static final String STRIPE_API_SECRET = "sk_live_998877665544332211_java_secret";

    private Connection connection;

    // 2. Vulnerable SQL Injection Sink (CWE-89)
    @GetMapping("/orders/search")
    public ResponseEntity<String> searchOrders(@RequestParam("q") String q) throws Exception {
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE item_name = '" + q + "'");
        return ResponseEntity.ok("Order results fetched");
    }

    // 3. Safe Parameterized SQL Decoy (CWE-89 Suppressed by B-2 Decoy Filter)
    @GetMapping("/orders/safe")
    public ResponseEntity<String> getOrderSafe(@RequestParam("id") String id) throws Exception {
        PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM orders WHERE id = ?");
        pstmt.setString(1, id);
        ResultSet rs = pstmt.executeQuery();
        return ResponseEntity.ok("Safe parameterized order lookup");
    }

    // 4. Vulnerable OS Command Injection Sink (CWE-78)
    @PostMapping("/diagnostics/ping")
    public ResponseEntity<String> pingHost(@RequestParam("host") String host) throws Exception {
        Process proc = Runtime.getRuntime().exec("ping -c 1 " + host);
        return ResponseEntity.ok("Pinged " + host);
    }

    // 5. Safe Command Execution Decoy (CWE-78 Suppressed by B-2 Decoy Filter)
    @PostMapping("/diagnostics/safe-ping")
    public ResponseEntity<String> pingHostSafe(@RequestParam("host") String host) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(Arrays.asList("ping", "-c", "1", host));
        return ResponseEntity.ok("Safe ProcessBuilder ping");
    }

    // 6. Vulnerable Reflected XSS Sink (CWE-79)
    @GetMapping("/reviews/preview")
    public ResponseEntity<String> previewReview(@RequestParam("comment") String comment) {
        return ResponseEntity.ok("<div class='review'>" + comment + "</div>");
    }

    // 7. Safe Escaped XSS Decoy (CWE-79 Suppressed by B-2 Decoy Filter)
    @GetMapping("/reviews/safe-preview")
    public ResponseEntity<String> previewReviewSafe(@RequestParam("comment") String comment) {
        String safeComment = HtmlUtils.htmlEscape(comment);
        return ResponseEntity.ok("<div class='review'>" + safeComment + "</div>");
    }

    // 8. Vulnerable Path Traversal Sink (CWE-22)
    @GetMapping("/invoices/download")
    public ResponseEntity<String> downloadInvoice(@RequestParam("file") String file) throws Exception {
        FileInputStream fis = new FileInputStream("/var/data/invoices/" + file);
        return ResponseEntity.ok("Invoice stream opened");
    }

    // 9. Vulnerable Open Redirect Sink (CWE-601)
    @GetMapping("/auth/redirect")
    public void loginRedirect(@RequestParam("next") String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(next);
    }
}
