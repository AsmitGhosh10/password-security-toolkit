#!/usr/bin/env bash
# Compiles, runs the tests and packages an executable jar. Needs JDK 17+.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf out && mkdir -p out/main out/test
javac --release 17 -d out/main $(find src/main/java -name '*.java')
cp -r src/main/resources/. out/main/

javac --release 17 -cp out/main -d out/test $(find src/test/java -name '*.java')
java -cp "out/main$( [[ "${OS:-}" == Windows_NT ]] && echo ';' || echo ':' )out/test" passwordtoolkit.ToolkitTest

jar --create --file out/password-toolkit.jar --main-class passwordtoolkit.Main -C out/main .
echo "Built out/password-toolkit.jar  ->  java -jar out/password-toolkit.jar"
