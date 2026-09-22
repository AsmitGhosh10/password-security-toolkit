package passwordtoolkit;

import java.io.Console;
import java.util.Locale;
import java.util.Scanner;

/** Interactive command-line menu for the toolkit. */
public final class Main {

    private static final Scanner IN = new Scanner(System.in);
    private static final PasswordStrengthChecker CHECKER = new PasswordStrengthChecker();

    public static void main(String[] args) {
        System.out.println("=== Password Security Toolkit ===");
        while (true) {
            System.out.println();
            System.out.println("1) Check password strength");
            System.out.println("2) Hash a password (salted SHA-256)");
            System.out.println("3) Verify a password against a hash");
            System.out.println("4) Generate a strong password");
            System.out.println("0) Exit");
            switch (prompt("Choose an option: ")) {
                case "1" -> checkStrength();
                case "2" -> hash();
                case "3" -> verify();
                case "4" -> generate();
                case "0", "q", "quit", "exit" -> { return; }
                default -> System.out.println("Unknown option.");
            }
        }
    }

    private static void checkStrength() {
        PasswordStrengthChecker.Result r = CHECKER.check(readSecret("Password: "));
        System.out.printf("Score: %d/100  Rating: %s  Entropy: ~%.0f bits%n", r.score(), r.rating(), r.entropyBits());
        if (r.feedback().isEmpty()) System.out.println("No issues found.");
        else r.feedback().forEach(f -> System.out.println(" - " + f));
    }

    private static void hash() {
        System.out.println("Stored value: " + PasswordHasher.hash(readSecret("Password: ")));
        System.out.println("(Hash the same password again and the output changes: the salt is random.)");
    }

    private static void verify() {
        String stored = prompt("Stored value (salt:hash): ");
        try {
            boolean ok = PasswordHasher.verify(readSecret("Password: "), stored);
            System.out.println(ok ? "Match." : "No match.");
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid stored value: " + e.getMessage());
        }
    }

    private static void generate() {
        PasswordGenerator.Rules rules = PasswordGenerator.Rules.defaults();
        String len = prompt("Length [16]: ");
        try {
            if (!len.isEmpty()) rules = rules.withLength(Integer.parseInt(len));
        } catch (NumberFormatException e) {
            System.out.println("Not a number, using 16.");
        }
        rules = rules.withLower(yes("Include lowercase? [Y/n]: ", true))
                .withUpper(yes("Include uppercase? [Y/n]: ", true))
                .withDigits(yes("Include digits? [Y/n]: ", true))
                .withSymbols(yes("Include symbols? [Y/n]: ", true))
                .withExcludeAmbiguous(yes("Exclude look-alike characters (Il1O0o)? [y/N]: ", false));
        try {
            String pw = PasswordGenerator.generate(rules);
            PasswordStrengthChecker.Result r = CHECKER.check(pw);
            System.out.println("Generated: " + pw);
            System.out.printf("Rating: %s (%d/100)%n", r.rating(), r.score());
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }
    }

    private static boolean yes(String question, boolean dflt) {
        String a = prompt(question).toLowerCase(Locale.ROOT);
        return a.isEmpty() ? dflt : a.startsWith("y");
    }

    private static String prompt(String text) {
        System.out.print(text);
        return IN.hasNextLine() ? IN.nextLine().strip() : "0";
    }

    /** Reads without echoing when run in a real terminal; falls back to plain input (IDEs, pipes). */
    private static String readSecret(String text) {
        Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword(text);
            return pw == null ? "" : new String(pw);
        }
        System.out.print(text);
        return IN.hasNextLine() ? IN.nextLine() : "";
    }
}
