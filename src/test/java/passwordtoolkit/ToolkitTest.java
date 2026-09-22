package passwordtoolkit;

import java.util.Set;

/**
 * Dependency-free test runner. Exits non-zero on the first failure so it can
 * run in CI without JUnit.
 */
public final class ToolkitTest {

    private static int passed = 0;

    public static void main(String[] args) {
        PasswordStrengthChecker checker = new PasswordStrengthChecker();

        // Strength checker
        check("common password is flagged and capped", () -> {
            var r = checker.check("Password123");
            return r.common() && r.score() <= 5;
        });
        check("empty password is very weak", () -> checker.check("").rating() == PasswordStrengthChecker.Rating.VERY_WEAK);
        check("long mixed password is very strong",
                () -> checker.check("T7#qLw!9zR@m2Kx$").rating() == PasswordStrengthChecker.Rating.VERY_STRONG);
        check("missing classes produce feedback", () -> checker.check("alllowercaseletters").feedback().size() >= 3);
        check("repeated run detected", () -> PasswordStrengthChecker.hasRepeatedRun("abccc1", 3));
        check("ascending sequence detected", () -> PasswordStrengthChecker.hasSequentialRun("xyzA", 3));
        check("descending sequence detected", () -> PasswordStrengthChecker.hasSequentialRun("k321", 3));
        check("no false sequence", () -> !PasswordStrengthChecker.hasSequentialRun("a1b2c3", 3));
        check("custom list is case-insensitive", () -> new PasswordStrengthChecker(Set.of("Secret")).check("SECRET").common());

        // Hasher
        check("hash verifies correct password", () -> PasswordHasher.verify("hunter2", PasswordHasher.hash("hunter2")));
        check("hash rejects wrong password", () -> !PasswordHasher.verify("hunter3", PasswordHasher.hash("hunter2")));
        check("same password, different salts", () -> !PasswordHasher.hash("same").equals(PasswordHasher.hash("same")));
        check("malformed stored value rejected", () -> {
            try { PasswordHasher.verify("x", "nocolon"); return false; }
            catch (IllegalArgumentException e) { return true; }
        });

        // Generator
        check("generator honours length and all classes", () -> {
            for (int i = 0; i < 200; i++) {
                String p = PasswordGenerator.generate(PasswordGenerator.Rules.defaults().withLength(12));
                if (p.length() != 12 || !p.chars().anyMatch(Character::isLowerCase) || !p.chars().anyMatch(Character::isUpperCase)
                        || !p.chars().anyMatch(Character::isDigit) || p.chars().allMatch(Character::isLetterOrDigit)) return false;
            }
            return true;
        });
        check("generator digits only", () -> PasswordGenerator.generate(new PasswordGenerator.Rules(20, false, false, true, false, false)).matches("\\d{20}"));
        check("generator excludes ambiguous", () -> {
            var rules = PasswordGenerator.Rules.defaults().withLength(200).withExcludeAmbiguous(true);
            return PasswordGenerator.generate(rules).chars().noneMatch(c -> PasswordGenerator.AMBIGUOUS.indexOf(c) >= 0);
        });
        check("generator rejects no classes", () -> {
            try { PasswordGenerator.generate(new PasswordGenerator.Rules(10, false, false, false, false, false)); return false; }
            catch (IllegalArgumentException e) { return true; }
        });
        check("generator rejects too-short length", () -> {
            try { PasswordGenerator.generate(PasswordGenerator.Rules.defaults().withLength(3)); return false; }
            catch (IllegalArgumentException e) { return true; }
        });

        System.out.println("All " + passed + " tests passed.");
    }

    private interface Check { boolean run(); }

    private static void check(String name, Check c) {
        if (!c.run()) {
            System.err.println("FAIL: " + name);
            System.exit(1);
        }
        passed++;
        System.out.println("ok   " + name);
    }
}
