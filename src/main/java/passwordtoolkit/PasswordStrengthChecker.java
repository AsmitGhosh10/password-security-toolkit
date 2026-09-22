package passwordtoolkit;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Scores a password on length, character variety and whether it appears in a
 * list of commonly used passwords.
 *
 * <p>The score runs from 0 to 100 and maps onto a {@link Rating}. Every
 * deduction also adds a human-readable hint to the result, so the user knows
 * how to improve the password, not just that it is weak.
 */
public final class PasswordStrengthChecker {

    /** Coarse strength bands derived from the numeric score. */
    public enum Rating {
        VERY_WEAK, WEAK, MODERATE, STRONG, VERY_STRONG;

        static Rating fromScore(int score) {
            if (score < 20) return VERY_WEAK;
            if (score < 40) return WEAK;
            if (score < 60) return MODERATE;
            if (score < 80) return STRONG;
            return VERY_STRONG;
        }
    }

    /** Outcome of a single check. */
    public record Result(int score, Rating rating, double entropyBits, boolean common, List<String> feedback) {}

    private static final String DEFAULT_LIST = "/common-passwords.txt";
    private static final int MIN_LENGTH = 8;
    private static final int GOOD_LENGTH = 12;

    private final Set<String> commonPasswords;

    /** Uses the common-password list bundled on the classpath. */
    public PasswordStrengthChecker() {
        this(loadList(DEFAULT_LIST));
    }

    /** Uses a caller-supplied list; entries are compared case-insensitively. */
    public PasswordStrengthChecker(Set<String> commonPasswords) {
        this.commonPasswords = new HashSet<>();
        for (String p : commonPasswords) this.commonPasswords.add(p.toLowerCase(Locale.ROOT));
    }

    public Result check(String password) {
        if (password == null) password = "";
        List<String> feedback = new ArrayList<>();
        int len = password.length();

        boolean lower = false, upper = false, digit = false, symbol = false;
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) lower = true;
            else if (Character.isUpperCase(c)) upper = true;
            else if (Character.isDigit(c)) digit = true;
            else symbol = true;
        }

        // Length: up to 40 points, 2.5 per character, capped at 16 chars.
        int score = (int) Math.min(40, len * 2.5);
        if (len < MIN_LENGTH) feedback.add("Use at least " + MIN_LENGTH + " characters (" + GOOD_LENGTH + "+ recommended).");
        else if (len < GOOD_LENGTH) feedback.add("Longer is stronger: aim for " + GOOD_LENGTH + "+ characters.");

        // Variety: 15 points per character class present.
        int classes = 0;
        if (lower) classes++; else feedback.add("Add lowercase letters.");
        if (upper) classes++; else feedback.add("Add uppercase letters.");
        if (digit) classes++; else feedback.add("Add digits.");
        if (symbol) classes++; else feedback.add("Add symbols such as ! @ # $.");
        score += classes * 15;

        // Patterns that make a password easier to guess.
        if (hasRepeatedRun(password, 3)) {
            score -= 10;
            feedback.add("Avoid repeating the same character (e.g. \"aaa\").");
        }
        if (hasSequentialRun(password, 3)) {
            score -= 10;
            feedback.add("Avoid sequences such as \"abc\" or \"123\".");
        }

        // A common password is weak no matter how it scores otherwise.
        boolean common = commonPasswords.contains(password.toLowerCase(Locale.ROOT));
        if (common) {
            score = Math.min(score, 5);
            feedback.add(0, "This is a commonly used password. Attackers try these first.");
        }

        score = Math.max(0, Math.min(100, score));
        return new Result(score, Rating.fromScore(score), entropyBits(len, lower, upper, digit, symbol), common, feedback);
    }

    /** Estimated brute-force entropy: length * log2(size of character pool). */
    static double entropyBits(int len, boolean lower, boolean upper, boolean digit, boolean symbol) {
        int pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0);
        return pool == 0 ? 0 : len * (Math.log(pool) / Math.log(2));
    }

    static boolean hasRepeatedRun(String s, int run) {
        int count = 1;
        for (int i = 1; i < s.length(); i++) {
            count = s.charAt(i) == s.charAt(i - 1) ? count + 1 : 1;
            if (count >= run) return true;
        }
        return false;
    }

    static boolean hasSequentialRun(String s, int run) {
        String lower = s.toLowerCase(Locale.ROOT);
        int up = 1, down = 1;
        for (int i = 1; i < lower.length(); i++) {
            int diff = lower.charAt(i) - lower.charAt(i - 1);
            up = diff == 1 ? up + 1 : 1;
            down = diff == -1 ? down + 1 : 1;
            if (up >= run || down >= run) return true;
        }
        return false;
    }

    private static Set<String> loadList(String resource) {
        InputStream in = PasswordStrengthChecker.class.getResourceAsStream(resource);
        if (in == null) throw new IllegalStateException("Missing classpath resource " + resource);
        Set<String> set = new HashSet<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (!line.isEmpty() && !line.startsWith("#")) set.add(line);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return set;
    }
}
