package demo;

/**
 * Stand-in for an application-defined SQL escaper. Registered as a
 * sanitizer in default-rules.yml. JavaSecScan does not validate the
 * actual logic — being named in the rule is sufficient to wash taint.
 */
public final class SqlSanitizer {

    private SqlSanitizer() {}

    public static String sanitize(String raw) {
        if (raw == null) return null;
        return raw.replace("'", "''").replace(";", "");
    }
}
