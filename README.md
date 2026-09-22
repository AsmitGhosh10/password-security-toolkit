# Password Security Toolkit

![CI](https://github.com/AsmitGhosh10/password-security-toolkit/actions/workflows/ci.yml/badge.svg)
![Java](https://img.shields.io/badge/Java-17%2B-orange)
![License: MIT](https://img.shields.io/badge/License-MIT-blue)

A command-line Java application that:

- **Evaluates password strength** based on length, character variety, common patterns and a list of commonly used passwords.
- **Hashes passwords with SHA-256 and a random salt** to show how passwords should be stored.
- **Generates strong random passwords** from rules you choose.

It uses only the Java standard library. There are no external dependencies.

---

## Features

### 1. Strength checker
Each password gets a score from 0 to 100 and a rating (`VERY_WEAK` … `VERY_STRONG`). The checker also lists specific ways to improve the password.

| Factor | Effect on score |
|---|---|
| Length | +2.5 per character, up to +40 (16+ characters) |
| Character variety | +15 for each class present: lowercase, uppercase, digits, symbols |
| Repeated characters (`aaa`) | −10 |
| Sequences (`abc`, `321`) | −10 |
| Found in common-password list | score capped at 5 |

The checker also reports an **entropy estimate**: `length × log2(character pool size)`, the number of bits a brute-force attacker would face.

The common-password list is in [`src/main/resources/common-passwords.txt`](src/main/resources/common-passwords.txt). Matching is case-insensitive. You can swap in a larger list, such as one from [SecLists](https://github.com/danielmiessler/SecLists), without changing any code.

### 2. Salted SHA-256 hashing
```
stored = base64(salt) + ":" + base64(SHA-256(salt || password))
```
- A new 16-byte salt from `SecureRandom` is used for every hash. Two users with the same password therefore get different stored values, which defeats precomputed rainbow tables.
- Verification uses `MessageDigest.isEqual`, a constant-time comparison. How long the check takes reveals nothing about how much of the hash matched.

> **Security note:** SHA-256 is designed to be fast, so a salted SHA-256 hash is still cheap to brute-force with a GPU. This project uses it to show the *concept* of salting. Real systems should use a slow, memory-hard algorithm such as **Argon2id**, **bcrypt** or **PBKDF2** with a high work factor.

### 3. Password generator
- Choose the length and which classes to include: lowercase, uppercase, digits and symbols.
- Optionally leave out look-alike characters (`I l 1 O 0 o`).
- Every selected class is guaranteed to appear at least once, and the result is shuffled.
- All randomness comes from `java.security.SecureRandom`.

---

## Getting started

**Requirements:** JDK 17 or newer, with `javac`, `java` and `jar` on your `PATH`.

```bash
git clone https://github.com/AsmitGhosh10/password-security-toolkit.git
cd password-security-toolkit
./build.sh                      # compile, run tests, build jar
java -jar out/password-toolkit.jar
```

On Windows, run `build.sh` from Git Bash or WSL. Or build manually in PowerShell:

```powershell
javac --release 17 -d out/main (Get-ChildItem -Recurse src/main/java -Filter *.java).FullName
Copy-Item -Recurse src/main/resources/* out/main/
jar --create --file out/password-toolkit.jar --main-class passwordtoolkit.Main -C out/main .
java -jar out/password-toolkit.jar
```

### Example session

```
=== Password Security Toolkit ===
1) Check password strength
2) Hash a password (salted SHA-256)
3) Verify a password against a hash
4) Generate a strong password
0) Exit
Choose an option: 1
Password:
Score: 5/100  Rating: VERY_WEAK  Entropy: ~65 bits
 - This is a commonly used password. Attackers try these first.
 - Longer is stronger: aim for 12+ characters.
 - Add symbols such as ! @ # $.
 - Avoid sequences such as "abc" or "123".

Choose an option: 2
Password:
Stored value: /39eAqZfBDJPGE9EBYlXMA==:lHJxW2ilsc0Q6qG5JTU5HdmHQaMHTk0ip+csxWvkoBA=

Choose an option: 4
Length [16]: 20
...
Generated: z<x#mtg-L%()Jc>d57vU
Rating: VERY_STRONG (100/100)
```

When run in a real terminal, password input is not echoed to the screen (`System.console().readPassword`).

---

## Project structure

```
password-security-toolkit/
├── build.sh                          # compile → test → package
├── src/main/java/passwordtoolkit/
│   ├── Main.java                     # interactive CLI menu
│   ├── PasswordStrengthChecker.java  # scoring, patterns, common-password lookup
│   ├── PasswordHasher.java           # salted SHA-256 hash + constant-time verify
│   └── PasswordGenerator.java        # SecureRandom generator with rules
├── src/main/resources/
│   └── common-passwords.txt          # wordlist (one password per line)
├── src/test/java/passwordtoolkit/
│   └── ToolkitTest.java              # dependency-free test runner (18 checks)
└── .github/workflows/ci.yml          # builds and tests on every push
```

## Using it as a library

```java
var checker = new PasswordStrengthChecker();
var result  = checker.check("Tr0ub4dor&3");
result.score();       // 0–100
result.rating();      // e.g. STRONG
result.feedback();    // List<String> of suggestions

String stored = PasswordHasher.hash("s3cret");
boolean ok    = PasswordHasher.verify("s3cret", stored);   // true

String pw = PasswordGenerator.generate(
        PasswordGenerator.Rules.defaults().withLength(24).withExcludeAmbiguous(true));
```

## Tests

`build.sh` runs `ToolkitTest`, which covers scoring, pattern detection, common-password matching, hash and verify round-trips, salt uniqueness, generator rules and invalid input. GitHub Actions runs it on every push.

## Possible extensions

- Replace SHA-256 with PBKDF2 (`javax.crypto`, available in the JDK) or Argon2
- Check passwords against the Have I Been Pwned k-anonymity API
- Build a JavaFX or Swing GUI

## License

[MIT](LICENSE) © 2026 Asmit Ghosh
