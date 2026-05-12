# JavaSecScan

Static vulnerability scanner for Java bytecode. Built on top of the [Soot](https://github.com/soot-oss/soot) program-analysis framework. Detects SQL injection (CWE-89), OS command injection (CWE-78), and path traversal (CWE-22) in `.jar` and `.class` artifacts.

The analysis runs intraprocedural forward taint propagation: any local that receives the return value of a configured *source* method is marked tainted; taint flows through copy assignments and casts; configured *sanitizers* wash taint; a *sink* call that receives a tainted argument is reported as a finding.

## Features

- **Soot-based taint analysis** — proper `ForwardFlowAnalysis<Unit, FlowSet<Local>>` over Jimple IR with fixed-point convergence.
- **YAML rule engine** — sources, sinks, and sanitizers as Soot method signatures.
- **Sanitizer support** — calls through registered sanitizers kill taint on the receiver, arguments, and return value.
- **REST API** (Spring Boot) — async scan jobs, JPA-backed findings store (H2 in dev, Postgres via Docker).
- **CLI mode** — JSON or SARIF on stdout, CI-friendly exit codes.
- **SARIF 2.1.0** output — GitHub Code Scanning ready, with CWE tags and `security-severity` scores.
- **OpenAPI 3 / Swagger UI** — interactive docs at `/swagger-ui/index.html`.
- **Diff endpoint** — `GET /api/scans/{id}/diff?against=…` returns only the findings introduced (or resolved) versus a baseline scan. Suitable as a PR gate.
- **GitHub Actions CI** — build, test, dogfood-scan the scanner's own jar, upload SARIF, and assert detection on a known-vulnerable sample.
- **Docker Compose** — API + Postgres in one command.

## Architecture

```
+-------------+      POST /api/scans       +--------------+
|   client    |  --------- jar ---------> |  REST API    |
+-------------+                            +--------------+
                                                  |
                                                  v
                                         +-----------------+
                                         | ScanService     | -> async worker pool
                                         +-----------------+
                                                  |
                                                  v
                                         +-----------------+
                                         |  SootAnalyzer   | --reads--> rules/*.yml
                                         |  TaintFlow      |    (sources/sinks/
                                         +-----------------+     sanitizers)
                                                  |
                                                  v
                                         +-----------------+
                                         |  SarifFormatter | --> SARIF 2.1.0
                                         +-----------------+
                                                  |
                                                  v
                                         +-----------------+
                                         |  H2 / Postgres  |
                                         +-----------------+
```

## How the taint analysis works

1. Soot loads the supplied jar and constructs Jimple (a typed 3-address IR) bodies for every application method.
2. For each method we build a `BriefUnitGraph` and run `TaintFlowAnalysis`, a `ForwardFlowAnalysis<Unit, FlowSet<Local>>`:
   - `flowThrough` treats `x = src()` as introducing taint on `x`.
   - Copy assignments (`x = y`) and casts (`x = (T) y`) propagate taint.
   - Calls whose arguments include a tainted local taint the return value (conservative over-approximation).
   - Any call to a configured *sanitizer* scrubs taint from its receiver, arguments, and return value.
   - Any other assignment kills taint on the LHS.
3. After convergence, we walk every invoke statement. If its method signature matches a configured *sink* and any argument is in the taint set at that program point, we emit a `Finding`.

The rule engine is a list of YAML entries (see `src/main/resources/rules/default-rules.yml`) with `sources`, `sinks`, and optional `sanitizers` given as Soot method signatures.

## Build

```
mvn -B package
```

To produce the runnable jar plus the vulnerable sample used by the end-to-end demo:

```
mvn -B -DskipTests package
mvn -B -f samples/vulnerable-app/pom.xml -DskipTests package
```

## Run as REST service

```
mvn spring-boot:run
# or:
java -jar target/javasecscan-0.1.0.jar
```

Submit a jar for scanning:

```
curl -F file=@samples/vulnerable-app/target/vulnerable-app-0.1.0.jar \
     http://localhost:8080/api/scans
# -> 202 ACCEPTED  {"id": 1, "status": "PENDING", ...}

curl http://localhost:8080/api/scans/1
# -> full report with findings

curl 'http://localhost:8080/api/scans/1?format=sarif'
# -> SARIF 2.1.0 document
```

Swagger UI is served at <http://localhost:8080/swagger-ui/index.html>; the raw OpenAPI document is at `/v3/api-docs`.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scans` | Upload a `.jar`. Returns 202 + scan id. |
| `GET`  | `/api/scans` | List all scans (without findings). |
| `GET`  | `/api/scans/{id}` | Full scan report. Add `?format=sarif` for SARIF. |
| `GET`  | `/api/scans/{id}/diff?against={baselineId}` | Findings introduced/resolved vs baseline. |

## Run as CLI

```
java -jar target/javasecscan-0.1.0.jar \
     --spring.profiles.active=cli \
     [--format=json|sarif] \
     samples/vulnerable-app/target/vulnerable-app-0.1.0.jar
```

Emits findings on stdout, or to a file when `--output=<path>` is given. Exit code is `0` when no findings, `1` otherwise — suitable for use as a CI gate that fails the build on any vulnerability. Use `--output` plus a shell guard if you want to inspect the report without failing the step.

## Sample vulnerable application

`samples/vulnerable-app` contains intentionally insecure code that triggers all three default rules **and** a sanitized control case that proves the sanitizer suppresses what would otherwise be a false positive. Build it with `mvn -f samples/vulnerable-app/pom.xml package`, then point the scanner at the produced jar.

Expected output: three findings (SQLI-001, CMDI-001, PATH-001). The `safeExample()` (parameterised query) and `safeWithSanitizer()` (runs through `SqlSanitizer.sanitize`) methods are correctly **not** flagged.

## Adding a rule

Edit `src/main/resources/rules/default-rules.yml`:

```yaml
- id: XSS-001
  name: Reflected XSS
  cwe: CWE-79
  severity: HIGH
  sources:
    - "javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)"
  sinks:
    - "java.io.PrintWriter: void println(java.lang.String)"
  sanitizers:
    - "org.owasp.encoder.Encode: java.lang.String forHtml(java.lang.String)"
```

Signatures use Soot's canonical form `<declaringClass: returnType methodName(paramTypes)>` (the angle brackets are added automatically at load time).

## Docker

```
docker compose up --build
```

Brings up the API and a Postgres instance.

## Continuous Integration

`.github/workflows/ci.yml` runs on every push and PR:

- **build-and-test** — Maven build + JUnit tests, uploads both jars as artifacts.
- **self-scan** — runs the scanner against its own jar (dogfooding) and uploads SARIF to GitHub Code Scanning so findings appear in the repo's *Security* tab.
- **scan-vulnerable-sample** — runs the scanner against the intentionally-vulnerable sample and **fails the build** if fewer than three planted vulnerabilities are detected (acts as a detection-regression gate).

`.github/workflows/release.yml` builds and pushes a Docker image to `ghcr.io/<owner>/javasecscan` on every `v*` tag.

## Known limitations

- Taint analysis is **intraprocedural**. Taint introduced in caller `f()` and passed as an argument to `g()` will not be tracked inside `g()`. Inline reproductions trigger; cross-method flows do not.
- No alias / pointer analysis — taint on object fields is not tracked.
- No taint laundering through string-format / regex methods.
- Source/sink matching is by exact Soot signature; overrides on subclasses must be enumerated.

## Roadmap

- Interprocedural analysis via Soot's Heros / IFDS solver.
- Pointer-aware field-sensitivity using Soot's SPARK points-to engine.
- Confidence scoring (path length, partial-sanitization heuristics).
- Plugin SPI for Java-coded rules (richer than signature matching).
- Evaluation against the OWASP Benchmark with precision/recall numbers in this README.

## End-to-end example

```
$ mvn -f samples/vulnerable-app/pom.xml -DskipTests package
$ mvn -DskipTests package
$ java -jar target/javasecscan-0.1.0.jar \
       --spring.profiles.active=cli \
       --format=sarif \
       samples/vulnerable-app/target/vulnerable-app-0.1.0.jar
{
  "$schema" : "https://json.schemastore.org/sarif-2.1.0.json",
  "version" : "2.1.0",
  "runs" : [ {
    "tool" : { "driver" : { "name" : "JavaSecScan", ... } },
    "results" : [
      { "ruleId" : "SQLI-001", "level" : "error",
        "locations" : [ { "physicalLocation" : {
          "artifactLocation" : { "uri" : "demo/VulnerableApp.java" },
          "region" : { "startLine" : 36 } } } ], ... },
      { "ruleId" : "CMDI-001", ... },
      { "ruleId" : "PATH-001", ... }
    ]
  } ]
}
```

The intentionally vulnerable sample triggers SQLi (CWE-89), command injection (CWE-78), and path traversal (CWE-22). The parameterised-query `safeExample()` and sanitizer-protected `safeWithSanitizer()` in the same jar are correctly **not** flagged.
