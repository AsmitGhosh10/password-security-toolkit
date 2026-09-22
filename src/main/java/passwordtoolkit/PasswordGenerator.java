package passwordtoolkit;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Generates random passwords from user-defined rules using {@link SecureRandom}.
 *
 * <p>Every enabled character class is guaranteed to appear at least once, and
 * the result is shuffled so those guaranteed characters are not always at the
 * start.
 */
public final class PasswordGenerator {

    static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static final String DIGITS = "0123456789";
    static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";
    /** Characters easily confused when read or typed by hand. */
    static final String AMBIGUOUS = "Il1O0o";

    /** Generation rules. Build with {@link #defaults()} and the {@code with*} methods. */
    public record Rules(int length, boolean lower, boolean upper, boolean digits, boolean symbols, boolean excludeAmbiguous) {
        public static Rules defaults() {
            return new Rules(16, true, true, true, true, false);
        }
        public Rules withLength(int n) { return new Rules(n, lower, upper, digits, symbols, excludeAmbiguous); }
        public Rules withLower(boolean b) { return new Rules(length, b, upper, digits, symbols, excludeAmbiguous); }
        public Rules withUpper(boolean b) { return new Rules(length, lower, b, digits, symbols, excludeAmbiguous); }
        public Rules withDigits(boolean b) { return new Rules(length, lower, upper, b, symbols, excludeAmbiguous); }
        public Rules withSymbols(boolean b) { return new Rules(length, lower, upper, digits, b, excludeAmbiguous); }
        public Rules withExcludeAmbiguous(boolean b) { return new Rules(length, lower, upper, digits, symbols, b); }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordGenerator() {}

    public static String generate(Rules rules) {
        List<String> pools = new ArrayList<>();
        if (rules.lower()) pools.add(filter(LOWER, rules));
        if (rules.upper()) pools.add(filter(UPPER, rules));
        if (rules.digits()) pools.add(filter(DIGITS, rules));
        if (rules.symbols()) pools.add(filter(SYMBOLS, rules));

        if (pools.isEmpty()) throw new IllegalArgumentException("Enable at least one character class.");
        if (rules.length() < pools.size())
            throw new IllegalArgumentException("Length must be at least " + pools.size() + " to include every selected class.");

        List<Character> chars = new ArrayList<>(rules.length());
        for (String pool : pools) chars.add(pick(pool));        // one from each class
        String all = String.join("", pools);
        while (chars.size() < rules.length()) chars.add(pick(all));
        Collections.shuffle(chars, RANDOM);

        StringBuilder sb = new StringBuilder(chars.size());
        for (char c : chars) sb.append(c);
        return sb.toString();
    }

    private static String filter(String pool, Rules rules) {
        if (!rules.excludeAmbiguous()) return pool;
        StringBuilder sb = new StringBuilder();
        for (char c : pool.toCharArray()) if (AMBIGUOUS.indexOf(c) < 0) sb.append(c);
        return sb.toString();
    }

    private static char pick(String pool) {
        return pool.charAt(RANDOM.nextInt(pool.length()));
    }
}
