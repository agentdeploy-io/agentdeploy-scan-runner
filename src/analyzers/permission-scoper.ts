import type { ScanFinding } from "../services/llm.js";

interface DockerInstruction {
  type: string;
  value: string;
  line: number;
}

export function analyzePermissions(
  files: Array<{ relativePath: string; content: string }>
): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const dockerfiles = files.filter(
    (f) =>
      f.relativePath === "Dockerfile" ||
      f.relativePath.endsWith("/Dockerfile") ||
      f.relativePath.endsWith(".dockerfile") ||
      f.relativePath === "docker-compose.yml" ||
      f.relativePath === "docker-compose.yaml"
  );

  for (const file of dockerfiles) {
    checkDockerPermissions(file, findings);
  }

  const envFiles = files.filter((f) => {
    const lower = f.relativePath.toLowerCase();
    return (
      lower.endsWith(".env") ||
      lower.endsWith(".env.example") ||
      lower.endsWith(".env.local") ||
      lower.endsWith(".env.production")
    );
  });

  for (const file of envFiles) {
    checkEnvFilePermissions(file, findings);
  }

  const k8sFiles = files.filter((f) => {
    const lower = f.relativePath.toLowerCase();
    return (
      lower.includes("deployment.yaml") ||
      lower.includes("deployment.yml") ||
      lower.includes("rbac.yaml") ||
      lower.includes("rbac.yml") ||
      lower.includes("pod.yaml") ||
      lower.includes("pod.yml")
    );
  });

  for (const file of k8sFiles) {
    checkKubernetesPermissions(file, findings);
  }

  const composeFiles = files.filter(
    (f) =>
      f.relativePath === "docker-compose.yml" ||
      f.relativePath === "docker-compose.yaml"
  );

  for (const file of composeFiles) {
    checkDockerComposePermissions(file, findings);
  }

  return findings;
}

function checkDockerPermissions(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  const lines = file.content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();

    if (/^USER\s+root/i.test(line)) {
      findings.push({
        severity: "critical",
        category: "permissions",
        ruleId: "PERM-DOCKER-ROOT",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Docker container runs as root",
        description:
          "The Dockerfile sets USER to root, granting the container full host privileges if escaped.",
        recommendation:
          "Create and use a non-root user in the Dockerfile.",
        evidence: { instruction: line },
      });
    }

    if (line === "USER 0" || /^USER\s+0\s*$/i.test(line)) {
      findings.push({
        severity: "critical",
        category: "permissions",
        ruleId: "PERM-DOCKER-ROOT-UID",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Docker container runs as root (UID 0)",
        description:
          "The Dockerfile explicitly uses UID 0 (root), which is unnecessary for most applications.",
        recommendation:
          "Use a non-root user or a specific non-zero UID.",
        evidence: { instruction: line },
      });
    }
  }
}

function checkDockerComposePermissions(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  const lines = file.content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim().toLowerCase();

    if (line.includes("privileged: true") || line.includes("privileged:true")) {
      findings.push({
        severity: "critical",
        category: "permissions",
        ruleId: "PERM-PRIVILEGED",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Privileged Docker container",
        description:
          "A service is configured with privileged: true, granting full access to host devices and capabilities.",
        recommendation:
          "Remove privileged mode and add only specific required capabilities.",
        evidence: { line: lines[i]!.trim() },
      });
    }

    if (line.includes("network_mode: host") || line.includes("network_mode:host")) {
      findings.push({
        severity: "high",
        category: "permissions",
        ruleId: "PERM-HOST-NETWORK",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Host network mode enabled",
        description:
          "A service uses host network mode, bypassing Docker network isolation.",
        recommendation:
          "Use bridge networking and explicitly expose required ports.",
        evidence: { line: lines[i]!.trim() },
      });
    }

    if (line.includes("cap_add:") || line.match(/^\s+-\s+cap_add:/i)) {
      findings.push({
        severity: "medium",
        category: "permissions",
        ruleId: "PERM-CAP-ADD",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Additional capabilities added",
        description:
          "Docker capabilities are being added beyond the default set.",
        recommendation:
          "Review each added capability and ensure it is strictly necessary.",
        evidence: { line: lines[i]!.trim() },
      });
    }
  }
}

function checkEnvFilePermissions(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  const lines = file.content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith("#")) continue;

    const match = line.match(/^([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$/);
    if (!match) continue;

    const [, key, value] = match;

    if (!key || !value) continue;

    const sensitivePatterns = [
      /PASSWORD/i,
      /SECRET/i,
      /PRIVATE_KEY/i,
      /ACCESS_TOKEN/i,
    ];

    if (
      sensitivePatterns.some((p) => p.test(key)) &&
      value !== "" &&
      !value.startsWith("your-") &&
      !value.startsWith("REPLACE") &&
      !value.startsWith("$")
    ) {
      findings.push({
        severity: "high",
        category: "permissions",
        ruleId: "PERM-ENV-SECRET",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Sensitive value in committed env file",
        description: `The key "${key}" appears to contain a sensitive value in a committed environment file.`,
        recommendation:
          "Remove sensitive values from committed env files. Use .env.example with placeholders instead.",
        evidence: { key, hasValue: value.length > 0 },
      });
    }
  }
}

function checkKubernetesPermissions(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  const lines = file.content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();

    if (line.includes("runAsUser: 0") || line.includes("runAsNonRoot: false")) {
      findings.push({
        severity: "critical",
        category: "permissions",
        ruleId: "PERM-K8S-ROOT",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Kubernetes pod runs as root",
        description:
          "The pod security context allows running as root user.",
        recommendation:
          "Set runAsNonRoot: true and use a non-zero runAsUser.",
        evidence: { line },
      });
    }

    if (line === "privileged: true" || line === "privileged:true") {
      findings.push({
        severity: "critical",
        category: "permissions",
        ruleId: "PERM-K8S-PRIVILEGED",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Kubernetes privileged container",
        description:
          "Container security context has privileged: true.",
        recommendation:
          "Remove privileged mode and use specific capabilities.",
        evidence: { line },
      });
    }

    if (line.includes("cluster-admin") || line.includes("ClusterRole")) {
      findings.push({
        severity: "high",
        category: "permissions",
        ruleId: "PERM-K8S-CLUSTER-ADMIN",
        tool: "custom-perms",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: "Cluster admin permissions requested",
        description:
          "RBAC configuration references cluster-admin or ClusterRole, which grants broad permissions.",
        recommendation:
          "Use namespace-scoped Roles with minimal required permissions.",
        evidence: { line },
      });
    }
  }
}
