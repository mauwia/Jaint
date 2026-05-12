package demo;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

/**
 * Intentionally vulnerable demo. Used only to exercise JavaSecScan.
 * Each method takes input from a source and passes it to a sink within
 * the same scope, since JavaSecScan's current taint analysis is
 * intraprocedural.
 * DO NOT REUSE.
 */
public class VulnerableApp {

    public static void main(String[] args) throws Exception {
        sqlInjection();
        commandInjection();
        pathTraversal();
        safeExample();
        safeWithSanitizer();
    }

    // CWE-89
    static void sqlInjection() throws SQLException {
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:demo");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name = '" + input + "'";
        stmt.executeQuery(query);
    }

    // CWE-78
    static void commandInjection() throws IOException {
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        Runtime.getRuntime().exec("ping " + input);
    }

    // CWE-22
    static void pathTraversal() throws IOException {
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        FileInputStream fis = new FileInputStream(input);
        fis.close();
    }

    // Sanitized — parameterized query should NOT be flagged for SQLi.
    static void safeExample() throws SQLException {
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:demo");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, input);
        ps.executeQuery();
    }

    // Sanitized via an application-defined sanitizer registered in the rule
    // — the SQLi finding for this method should be suppressed.
    static void safeWithSanitizer() throws SQLException {
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        String safe = SqlSanitizer.sanitize(input);
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:demo");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + safe + "'");
    }
}
