import type { StudioConfig } from '../../shared/config.js';
import { noProxy, reg, type FileMap } from './util.js';

export function ciFiles(c: StudioConfig): FileMap {
  const f: FileMap = {};
  const R = reg(c);
  const tags = `  tags: [${c.gitlab.runnerTags.map(t => JSON.stringify(t)).join(', ')}]`;
  const s = c.scanners;
  const scanJobs: string[] = [];
  if (s.zap) scanJobs.push(`dd:scan:zap:
  extends: .dd-scanner
  image: ${R}/zap:pinned
  variables: { DOJO_SCANNER: zap }
  script:
    - mkdir -p reports
    # Baseline (passive) scan of the internal target; active scans run in the scheduled DAST pipeline.
    - zap-baseline.py -t "$DAST_TARGET_URL" -J reports/zap.json -I || test -s reports/zap.json
  rules:
    - if: '$DAST_TARGET_URL && ($CI_PIPELINE_SOURCE == "schedule" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH)'
`);
  if (s.trivy) scanJobs.push(`dd:scan:trivy:
  extends: .dd-scanner
  image: { name: ${R}/trivy:pinned, entrypoint: [""] }
  variables: { DOJO_SCANNER: trivy }
  script:
    - mkdir -p reports
    - trivy image --db-repository "$TRIVY_DB_REPOSITORY" --java-db-repository "$TRIVY_JAVA_DB_REPOSITORY" --format json -o reports/trivy.json "$DOJO_SCAN_IMAGE"
  rules:
    - if: '$DOJO_SCAN_IMAGE'
`);
  if (s.trivySbom) scanJobs.push(`dd:scan:trivy-sbom:
  extends: .dd-scanner
  image: { name: ${R}/trivy:pinned, entrypoint: [""] }
  variables: { DOJO_SCANNER: trivy-sbom }
  script:
    - mkdir -p reports
    - trivy image --db-repository "$TRIVY_DB_REPOSITORY" --scanners vuln --format cyclonedx -o reports/sbom.cdx.json "$DOJO_SCAN_IMAGE"
  rules:
    - if: '$DOJO_SCAN_IMAGE'
`);
  if (s.grypeSbom) scanJobs.push(`dd:scan:grype-sbom:
  extends: .dd-scanner
  image: { name: ${R}/grype:pinned, entrypoint: [""] }
  needs: [${s.trivySbom ? '"dd:scan:trivy-sbom"' : ''}]
  variables: { DOJO_SCANNER: grype-sbom, GRYPE_DB_UPDATE_URL: "$GRYPE_DB_MIRROR_URL", GRYPE_CHECK_FOR_APP_UPDATE: "false" }
  script:
    - mkdir -p reports
    - grype sbom:reports/sbom.cdx.json -o json --file reports/grype.json
  rules:
    - if: '$DOJO_SCAN_IMAGE'
`);
  if (s.semgrep) scanJobs.push(`dd:scan:semgrep:
  extends: .dd-scanner
  image: ${R}/semgrep:pinned
  variables: { DOJO_SCANNER: semgrep, SEMGREP_SEND_METRICS: "off" }
  script:
    - mkdir -p reports
    # Rules are vendored (no registry download): \${SEMGREP_RULES:-ci/semgrep-rules}
    - semgrep scan --config "\${SEMGREP_RULES:-ci/semgrep-rules}" --metrics=off --json -o reports/semgrep.json . || test -s reports/semgrep.json
`);
  if (s.gitleaks) scanJobs.push(`dd:scan:gitleaks:
  extends: .dd-scanner
  image: { name: ${R}/gitleaks:pinned, entrypoint: [""] }
  variables: { DOJO_SCANNER: gitleaks }
  script:
    - mkdir -p reports
    - gitleaks detect --source . --report-format json --report-path reports/gitleaks.json --exit-code 0
`);
  if (s.sarif) scanJobs.push(`dd:scan:sarif:
  extends: .dd-scanner
  variables: { DOJO_SCANNER: sarif }
  script:
    - mkdir -p reports && cp "\${SARIF_REPORT:?set SARIF_REPORT}" reports/report.sarif
  rules:
    - if: '$SARIF_REPORT'
`);

  f['ci/defectdojo-jobs.gitlab-ci.yml'] = `# DefectDojo GovCloud jobs - INCLUDE-ONLY. Consumers add:
#   include:
#     - project: '${c.gitlab.projectPath}'
#       ref: ${c.gitlab.defaultBranch}
#       file: ci/defectdojo-jobs.gitlab-ci.yml
# and set DOJO_PRODUCT / DOJO_PLATFORM (+ DOJO_SCAN_IMAGE, DAST_TARGET_URL as needed).
#
# Zero secrets in GitLab CI/CD variables: jobs authenticate to AWS with GitLab OIDC (id_tokens ->
# AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN, natively supported by the AWS CLI) and read secrets from
# AWS Secrets Manager at runtime via scripts/ci_secrets.py. TLS verification is never disabled: the
# combined CA bundle is exported for Python, AWS CLI, git, curl, node and the runner.

variables:
  DOJO_REGISTRY: "${R}"
  DOJO_AUTOMATION_IMAGE: "${R}/dojo-automation:pinned"
  DOJO_PRODUCT: "$CI_PROJECT_NAME"
  DOJO_PLATFORM: "EKS"
  DOJO_ENGAGEMENT: "CI/CD $CI_DEFAULT_BRANCH"
  DOJO_AUTOMATION_CONFIG: "config/defectdojo-automation.json"
  AWS_REGION: "${c.aws.region}"
  AWS_DEFAULT_REGION: "${c.aws.region}"
  AWS_USE_FIPS_ENDPOINT: "true"
  AWS_STS_REGIONAL_ENDPOINTS: "regional"
  AWS_ROLE_ARN: "${c.gitlab.awsRoleArn}"
  HTTPS_PROXY: "${c.network.httpsProxy}"
  HTTP_PROXY: "${c.network.httpsProxy}"
  NO_PROXY: "${noProxy(c)}"
  TRIVY_DB_REPOSITORY: "${R}/trivy-db"
  TRIVY_JAVA_DB_REPOSITORY: "${R}/trivy-java-db"
  GRYPE_DB_MIRROR_URL: "${c.gitlab.url}/api/v4/projects/secops%2Fgrype-db/packages/generic/grype-db/latest/listing.json"
  GIT_DEPTH: "20"

.dd-base:
  image: "$DOJO_AUTOMATION_IMAGE"
${tags}
  id_tokens:
    AWS_ID_TOKEN:
      aud: "${c.gitlab.url}"
  before_script:
    - mkdir -p .ca
    - python3 scripts/build_ca_bundle.py --internal ${c.trust.internalCaFile} \${CI_SERVER_TLS_CA_FILE:+--internal "$CI_SERVER_TLS_CA_FILE"} --out .ca/ca-bundle.pem --print-env > .ca/env
    - . .ca/env
    - git config --global http.sslCAInfo "$GIT_SSL_CAINFO"
    - printf '%s' "$AWS_ID_TOKEN" > .ca/web-identity-token && export AWS_WEB_IDENTITY_TOKEN_FILE="$PWD/.ca/web-identity-token"
  interruptible: true

.dd-secrets:
  # Fetch only the secrets this job needs; values exist only in the job process environment.
  - eval "$(python3 scripts/ci_secrets.py DD_API_TOKEN=${c.aws.secretsPrefix}ci-automation:dd_api_token)"

.dd-scanner:
${tags}
  stage: dd-scan
  artifacts:
    when: always
    expire_in: 7 days
    paths: [reports/]

stages: [dd-validate, dd-scan, dd-import, dd-publish]

dd:validate:python:
  extends: .dd-base
  stage: dd-validate
  script:
    - python3 -m unittest discover -s tests -t . -v
    - python3 scripts/validate_config.py
  rules:
    - changes: ["scripts/**/*", "tests/**/*", "config/**/*"]

dd:validate:submissions:
  extends: .dd-base
  stage: dd-validate
  script:
    # Validates only the submission files changed in this MR (JSON + office documents).
    - python3 scripts/submissions.py validate-diff --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      changes:
        - "submissions/**/*.json"
        - "submissions/**/*.csv"
        - "submissions/**/*.xlsx"
        - "submissions/**/*.ods"
        - "submissions/**/*.xml"
        - "submissions/**/*.docx"

dd:validate:helm:
  extends: .dd-base
  stage: dd-validate
  image: ${R}/helm:pinned
  script:
    - helm repo add defectdojo "${c.helm.chartRepo}" --ca-file "$SSL_CERT_FILE"
    - helm template ${c.helm.releaseName} defectdojo/defectdojo --version ${c.helm.chartVersion} -n ${c.kubernetes.namespace} -f deploy/values.yaml ${c.database.mode === 'rds' ? '-f deploy/values-rds.yaml ' : ''}--post-renderer deploy/post-renderer/mirror-images.py > rendered.yaml
    - python3 scripts/verify_rendered.py rendered.yaml --registry "$DOJO_REGISTRY"
    - cp .ca/ca-bundle.pem deploy/automation/ca-bundle.pem
    - kubectl kustomize deploy/automation > automation.yaml
    - python3 scripts/verify_rendered.py automation.yaml --registry "$DOJO_REGISTRY"
  artifacts: { paths: [rendered.yaml, automation.yaml], expire_in: 7 days }
  rules:
    - exists: ["deploy/images.lock.json"]
      changes: ["deploy/**/*", "config/**/*"]

dd:validate:cloudformation:
  extends: .dd-base
  stage: dd-validate
  script:
    - for t in cloudformation/*.yaml; do aws cloudformation validate-template --template-body "file://$t" > /dev/null && echo "ok $t"; done
  rules:
    - changes: ["cloudformation/**/*"]

${scanJobs.join('\n')}
dd:import:
  extends: .dd-base
  stage: dd-import
  needs:
${['zap', 'trivy', 'trivy-sbom', 'grype-sbom', 'semgrep', 'gitleaks', 'sarif'].filter(n => ({ zap: s.zap, trivy: s.trivy, 'trivy-sbom': s.trivySbom, 'grype-sbom': s.grypeSbom, semgrep: s.semgrep, gitleaks: s.gitleaks, sarif: s.sarif } as Record<string, boolean>)[n]).map(n => `    - { job: "dd:scan:${n}", optional: true }`).join('\n')}
  script:
    - !reference [.dd-secrets]
    # Pre-upload SHA-256 fingerprint de-duplication + cross-scanner de-dup, then reimport (close-on-fix).
    - |
      for r in reports/*; do
        [ -f "$r" ] || continue
        python3 scripts/intake.py import-file --file "$r" --product "$DOJO_PRODUCT" --engagement "$DOJO_ENGAGEMENT" --platform "$DOJO_PLATFORM"
      done
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_PIPELINE_SOURCE == "schedule"'

dd:submissions:import:
  extends: .dd-base
  stage: dd-import
  script:
    - !reference [.dd-secrets]
    - |
      git diff --name-only --diff-filter=AM "$CI_COMMIT_BEFORE_SHA" "$CI_COMMIT_SHA" -- submissions/ | while read -r f; do
        case "$f" in *.json|*.csv|*.xlsx|*.ods|*.xml|*.docx) python3 scripts/intake.py import-file --file "$f" --product manual ;; esac
      done
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
      changes: ["submissions/**/*"]

pages:
  extends: .dd-base
  stage: dd-publish
  script:
    - !reference [.dd-secrets]
    - aws s3 cp "s3://${c.aws.stateBucket}/automation-state/metrics/history.jsonl" .state/metrics/history.jsonl --only-show-errors || true
    - export DOJO_STATE_DIR="$PWD/.state"
    - python3 scripts/metrics.py snapshot
    - python3 scripts/metrics.py build --out public
    - aws s3 cp .state/metrics/history.jsonl "s3://${c.aws.stateBucket}/automation-state/metrics/history.jsonl" --sse aws:kms --sse-kms-key-id "${c.aws.kmsKeyAlias}" --only-show-errors
  artifacts: { paths: [public] }
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $DOJO_JOB != "feeds"'

${c.confluence.enabled ? `dd:confluence:
  extends: .dd-base
  stage: dd-publish
  needs: [pages]
  script:
    - eval "$(python3 scripts/ci_secrets.py ${c.confluence.mode === 'cloud' ? 'CONFLUENCE_API_TOKEN' : 'CONFLUENCE_PAT'}=${c.aws.secretsPrefix}ci-automation:confluence_token)"
    - python3 scripts/confluence.py publish --metrics public/data/metrics.json
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $DOJO_JOB != "feeds"'
` : ''}
dd:feeds:sync:
  extends: .dd-base
  stage: dd-publish
  script:
    - eval "$(python3 scripts/ci_secrets.py NVD_API_KEY=${c.aws.secretsPrefix}ci-automation:nvd_api_key GITHUB_TOKEN=${c.aws.secretsPrefix}ci-automation:github_token)"
    - export DOJO_STATE_DIR="$PWD/.state"
    - python3 scripts/sync_feeds.py sync
    - python3 scripts/sync_feeds.py bundle create --out "bundles/threat-intel-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
  artifacts: { paths: [bundles/], expire_in: 30 days }
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule" && $DOJO_JOB == "feeds"'

dd:feeds:offline-import:
  extends: .dd-base
  stage: dd-publish
  when: manual
  script:
    - export DOJO_STATE_DIR="$PWD/.state"
    - python3 scripts/sync_feeds.py bundle import --bundle "$DOJO_BUNDLE" --sha256 "$DOJO_BUNDLE_SHA256"
    - python3 scripts/sync_feeds.py check-staleness
  rules:
    - if: '$DOJO_BUNDLE && $DOJO_BUNDLE_SHA256'

dd:mirror-images:
  extends: .dd-base
  stage: dd-publish
  when: manual
  script:
    - python3 scripts/mirror_images.py --images deploy/images.json --lock deploy/images.lock.json
  artifacts: { paths: [deploy/images.lock.json] }
`;
  f['.gitlab-ci.yml'] = `# Root pipeline for this IaC repository; all job logic lives in the include-only file.
include:
  - local: ci/defectdojo-jobs.gitlab-ci.yml

workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_PIPELINE_SOURCE == "web"'

variables:
  DOJO_PRODUCT: "defectdojo-platform"
`;
  f['ci/semgrep-rules/README.md'] = `Vendor Semgrep rule packs here (e.g. exported from an internal mirror). The CI job never downloads rules
from the public registry. Example: \`semgrep --config p/default --dump-config\` on a connected host, then
review and commit.\n`;
  return f;
}

export function gradleFiles(c: StudioConfig): FileMap {
  const f: FileMap = {};
  const proxy = new URL(c.network.httpsProxy);
  const nonProxy = c.network.noProxy.filter(x => !x.includes('/')).map(x => (x.startsWith('.') ? '*' + x : x)).join('|');
  f['settings.gradle.kts'] = `rootProject.name = "${c.project.name}"\n`;
  f['gradle.properties'] = `# Proxy + trust for Gradle itself (dependency resolution is not needed: the build only orchestrates CLIs).
systemProp.https.proxyHost=${proxy.hostname}
systemProp.https.proxyPort=${proxy.port || '3128'}
systemProp.http.proxyHost=${proxy.hostname}
systemProp.http.proxyPort=${proxy.port || '3128'}
systemProp.https.nonProxyHosts=${nonProxy}
systemProp.http.nonProxyHosts=${nonProxy}
# PKCS#12 trust store produced by: python3 scripts/build_ca_bundle.py --internal ${c.trust.internalCaFile} --out .ca/ca-bundle.pem --pkcs12 .ca/truststore.p12
systemProp.javax.net.ssl.trustStore=.ca/truststore.p12
systemProp.javax.net.ssl.trustStoreType=PKCS12
systemProp.javax.net.ssl.trustStorePassword=changeit
org.gradle.caching=false
org.gradle.configuration-cache=false
`;
  f['build.gradle.kts'] = `// Gradle Kotlin DSL task runner for the DefectDojo GovCloud IaC repository.
// Every task shells out to pinned CLIs (python3 stdlib, helm, kubectl, aws) - no plugins, no dependencies.
// ./gradlew tasks --group defectdojo

val chartRepo = "${c.helm.chartRepo}"
val chartVersion = "${c.helm.chartVersion}"
val releaseName = "${c.helm.releaseName}"
val namespace = "${c.kubernetes.namespace}"
val registry = "${reg(c)}"
val region = "${c.aws.region}"
val useRds = providers.gradleProperty("rds").map { it.toBoolean() }.getOrElse(${c.database.mode === 'rds'})
val caBundle = layout.projectDirectory.file(".ca/ca-bundle.pem").asFile.absolutePath

fun Exec.dojoEnv() {
    environment("AWS_USE_FIPS_ENDPOINT", "true")
    environment("AWS_REGION", region)
    environment("AWS_DEFAULT_REGION", region)
    environment("SSL_CERT_FILE", caBundle)
    environment("AWS_CA_BUNDLE", caBundle)
    environment("REQUESTS_CA_BUNDLE", caBundle)
    environment("GIT_SSL_CAINFO", caBundle)
    environment("DOJO_CA_BUNDLE", caBundle)
    environment("HTTPS_PROXY", "${c.network.httpsProxy}")
    environment("NO_PROXY", "${noProxy(c)}")
    environment("DOJO_AUTOMATION_CONFIG", layout.projectDirectory.file("config/defectdojo-automation.json").asFile.absolutePath)
}

val helmValues = buildList {
    add("-f"); add("deploy/values.yaml")
    if (useRds) { add("-f"); add("deploy/values-rds.yaml") }
    add("--post-renderer"); add("deploy/post-renderer/mirror-images.py")
}

tasks.register<Exec>("caBundle") {
    group = "defectdojo"; description = "Build the combined system + internal CA bundle (PEM + PKCS#12 for Java/Gradle)"
    commandLine("python3", "scripts/build_ca_bundle.py", "--internal", "${c.trust.internalCaFile}", "--out", ".ca/ca-bundle.pem", "--pkcs12", ".ca/truststore.p12")
}

tasks.register<Exec>("pythonTest") {
    group = "defectdojo"; description = "Run the stdlib-only Python unit tests"
    commandLine("python3", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v")
}

tasks.register<Exec>("validateConfig") {
    group = "defectdojo"; description = "Validate config/defectdojo-automation.json"
    dojoEnv(); commandLine("python3", "scripts/validate_config.py")
}

tasks.register<Exec>("helmRepo") {
    group = "defectdojo"; description = "Add the pinned DefectDojo chart repository"
    dependsOn("caBundle"); dojoEnv()
    commandLine("helm", "repo", "add", "defectdojo", chartRepo, "--ca-file", caBundle, "--force-update")
}

tasks.register<Exec>("helmTemplate") {
    group = "defectdojo"; description = "Render the chart through the image-mirroring post-renderer"
    dependsOn("helmRepo"); dojoEnv()
    val out = layout.buildDirectory.file("rendered.yaml").get().asFile
    doFirst { out.parentFile.mkdirs(); standardOutput = out.outputStream() }
    commandLine(listOf("helm", "template", releaseName, "defectdojo/defectdojo", "--version", chartVersion, "-n", namespace) + helmValues)
}

tasks.register<Exec>("verifyRendered") {
    group = "defectdojo"; description = "Policy gate: digests, internal registry, CA/proxy env, no Secrets, FIPS ALB, hardened CronJobs"
    dependsOn("helmTemplate")
    commandLine("python3", "scripts/verify_rendered.py", layout.buildDirectory.file("rendered.yaml").get().asFile.absolutePath, "--registry", registry)
}

tasks.register<Exec>("deploy") {
    group = "defectdojo"; description = "helm upgrade --install (atomic) + automation manifests"
    dependsOn("verifyRendered", "validateConfig"); dojoEnv()
    commandLine(listOf("helm", "upgrade", "--install", releaseName, "defectdojo/defectdojo", "--version", chartVersion,
        "-n", namespace, "--create-namespace", "--atomic", "--timeout", "15m") + helmValues)
    doLast { exec { dojoEnv(); commandLine("kubectl", "apply", "-k", "deploy/automation") } }
}

tasks.register<Exec>("mirrorImages") {
    group = "defectdojo"; description = "Mirror pinned images into the GitLab registry and write deploy/images.lock.json"
    dependsOn("caBundle"); dojoEnv()
    commandLine("python3", "scripts/mirror_images.py", "--images", "deploy/images.json", "--lock", "deploy/images.lock.json")
}

tasks.register<Exec>("deployBuckets") {
    group = "defectdojo"; description = "Deploy the SSE-KMS S3 intake/state buckets (CloudFormation)"
    dojoEnv()
    commandLine("aws", "cloudformation", "deploy", "--stack-name", "${c.project.name}-buckets", "--template-file", "cloudformation/intake-bucket.yaml", "--no-fail-on-empty-changeset")
}

tasks.register<Exec>("deployIam") {
    group = "defectdojo"; description = "Deploy IRSA + GitLab OIDC roles (CloudFormation)"
    dependsOn("deployBuckets"); dojoEnv()
    commandLine("aws", "cloudformation", "deploy", "--stack-name", "${c.project.name}-iam", "--template-file", "cloudformation/iam-roles.yaml", "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset")
}

tasks.register<Exec>("syncFeeds") {
    group = "defectdojo"; description = "Online threat-feed sync through the proxy allowlist"
    dojoEnv(); commandLine("python3", "scripts/sync_feeds.py", "sync")
}

tasks.register<Exec>("bundleOffline") {
    group = "defectdojo"; description = "Create a SHA-256 verified air-gap bundle from the current snapshot"
    dojoEnv(); commandLine("python3", "scripts/sync_feeds.py", "bundle", "create", "--out", "build/threat-intel-bundle.tar.gz")
}

tasks.register<Exec>("importOffline") {
    group = "defectdojo"; description = "Import an air-gap bundle: -Pbundle=path [-Psha256=hex]"
    dojoEnv()
    val bundle = providers.gradleProperty("bundle").getOrElse("build/threat-intel-bundle.tar.gz")
    val sha = providers.gradleProperty("sha256").orNull
    commandLine(listOf("python3", "scripts/sync_feeds.py", "bundle", "import", "--bundle", bundle) + (if (sha != null) listOf("--sha256", sha) else emptyList()))
}

tasks.register<Exec>("buildPages") {
    group = "defectdojo"; description = "Build the strict-CSP GitLab Pages dashboard into public/"
    dojoEnv(); commandLine("python3", "scripts/metrics.py", "build", "--out", "public")
}

tasks.register<Exec>("templates") {
    group = "defectdojo"; description = "Generate the .xlsx/.csv engagement templates"
    doFirst { file("build").mkdirs() }
    commandLine("python3", "scripts/office_templates.py", "--format", "xlsx", "--out", "build/engagement-template.xlsx")
}

tasks.register("check") {
    group = "verification"; dependsOn("pythonTest", "validateConfig")
}
`;
  return f;
}
