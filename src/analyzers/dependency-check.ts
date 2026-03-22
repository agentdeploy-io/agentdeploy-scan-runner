import type { ScanFinding } from "../services/llm.js";

const KNOWN_VULNERABLE_PACKAGES: Record<string, { severity: "critical" | "high"; cve: string; description: string }> = {
  "event-stream@3.3.6": {
    severity: "critical",
    cve: "CVE-2018-1999023",
    description: "Compromised package with malicious flatmap-stream dependency",
  },
  "ua-parser-js@0.7.29": {
    severity: "critical",
    cve: "CVE-2021-27292",
    description: "Compromised package containing cryptominer and password stealer",
  },
  "colors@1.4.1": {
    severity: "high",
    cve: "GHSA-3cqf-953p-h5cp",
    description: "Infinite loop / denial of service via malicious update",
  },
  "faker@6.6.6": {
    severity: "high",
    cve: "GHSA-5wmg-2w5v-33f4",
    description: "Compromised package with malicious code after maintainer sabotage",
  },
};

const TYPOSQUAT_CANDIDATES: Array<{ fake: string; real: string }> = [
  { fake: "crossenv", real: "cross-env" },
  { fake: "cross-env.js", real: "cross-env" },
  { fake: "expressjs", real: "express" },
  { fake: "mongoose.js", real: "mongoose" },
  { fake: "lodashs", real: "lodash" },
  { fake: "react-domm", real: "react-dom" },
  { fake: "reactjs", real: "react" },
  { fake: "nodemailer.js", real: "nodemailer" },
  { fake: "axios.js", real: "axios" },
  { fake: "chalk-js", real: "chalk" },
  { fake: "bluebird.js", real: "bluebird" },
  { fake: "debug.js", real: "debug" },
  { fake: "request.js", real: "request" },
];

const SUSPICIOUS_PACKAGE_PATTERNS = [
  /^[a-z]{1,3}$/,
  /^[a-z]+-[a-z]+-[a-z]+-[a-z]+$/,
  /bitcoin|crypto|wallet|steal|hack|exploit/i,
];

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export function analyzeDependencies(
  files: Array<{ relativePath: string; content: string }>
): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const packageJsonFile = files.find(
    (f) => f.relativePath === "package.json" || f.relativePath.endsWith("/package.json")
  );

  if (packageJsonFile) {
    checkPackageJson(packageJsonFile, findings);
  }

  const requirementsFile = files.find(
    (f) =>
      f.relativePath === "requirements.txt" ||
      f.relativePath.endsWith("/requirements.txt")
  );

  if (requirementsFile) {
    checkRequirementsTxt(requirementsFile, findings);
  }

  const mcpManifest = files.find(
    (f) =>
      f.relativePath === "mcp.json" ||
      f.relativePath.includes("mcp.json") ||
      f.relativePath.includes(".mcp")
  );

  if (mcpManifest) {
    checkMcpManifest(mcpManifest, findings);
  }

  return findings;
}

function checkPackageJson(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  let pkg: PackageJson;
  try {
    pkg = JSON.parse(file.content) as PackageJson;
  } catch {
    findings.push({
      severity: "medium",
      category: "dependencies",
      ruleId: "DEP-MALFORMED-JSON",
      tool: "custom-deps",
      filePath: file.relativePath,
      lineStart: 1,
      title: "Malformed package.json",
      description: "package.json contains invalid JSON and could not be parsed.",
      recommendation: "Fix the JSON syntax in package.json.",
    });
    return;
  }

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  for (const [name, version] of Object.entries(allDeps)) {
    const cleanVersion = version.replace(/^[~^>=<]/, "");
    const key = `${name}@${cleanVersion}`;

    const vuln = KNOWN_VULNERABLE_PACKAGES[key];
    if (vuln) {
      findings.push({
        severity: vuln.severity,
        category: "dependencies",
        ruleId: "DEP-KNOWN-VULN",
        tool: "custom-deps",
        filePath: file.relativePath,
        lineStart: findDependencyLine(file.content, name),
        title: `Known vulnerable package: ${name}@${cleanVersion}`,
        description: vuln.description,
        recommendation: `Update ${name} to a safe version or remove it. (${vuln.cve})`,
        evidence: { package: name, version: cleanVersion, cve: vuln.cve },
      });
    }

    for (const { fake, real } of TYPOSQUAT_CANDIDATES) {
      if (name === fake) {
        findings.push({
          severity: "high",
          category: "dependencies",
          ruleId: "DEP-TYPOSQUAT",
          tool: "custom-deps",
          filePath: file.relativePath,
          lineStart: findDependencyLine(file.content, name),
          title: `Possible typosquat: ${name}`,
          description: `Package name "${name}" is suspiciously similar to "${real}". This may be a typosquatting attack.`,
          recommendation: `Verify you intended to use "${name}" and not "${real}".`,
          evidence: { package: name, expected: real },
        });
      }
    }

    if (SUSPICIOUS_PACKAGE_PATTERNS.some((p) => p.test(name))) {
      findings.push({
        severity: "medium",
        category: "dependencies",
        ruleId: "DEP-SUSPICIOUS-NAME",
        tool: "custom-deps",
        filePath: file.relativePath,
        lineStart: findDependencyLine(file.content, name),
        title: `Suspicious package name: ${name}`,
        description: `Package "${name}" matches patterns associated with malicious packages.`,
        recommendation: `Review the package "${name}" for legitimacy before installing.`,
        evidence: { package: name },
      });
    }

    if (version === "*" || version === "latest" || version === "") {
      findings.push({
        severity: "medium",
        category: "dependencies",
        ruleId: "DEP-NO-PINNING",
        tool: "custom-deps",
        filePath: file.relativePath,
        lineStart: findDependencyLine(file.content, name),
        title: `Unpinned dependency: ${name}`,
        description: `Package "${name}" uses an unpinned version specifier, which allows any version including potentially compromised releases.`,
        recommendation: `Pin "${name}" to a specific version or use a lockfile.`,
        evidence: { package: name, version },
      });
    }
  }
}

function checkRequirementsTxt(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  const lines = file.content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;

    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(.*)?$/);
    if (!match) continue;

    const [, name, versionSpec] = match;

    if (!versionSpec || versionSpec.trim() === "" || versionSpec.includes("*")) {
      findings.push({
        severity: "medium",
        category: "dependencies",
        ruleId: "DEP-UNPINNED-PYTHON",
        tool: "custom-deps",
        filePath: file.relativePath,
        lineStart: i + 1,
        title: `Unpinned Python dependency: ${name}`,
        description: `Package "${name}" has no version pin, allowing any version to be installed.`,
        recommendation: `Pin "${name}" to a specific version in requirements.txt.`,
        evidence: { package: name },
      });
    }
  }
}

function checkMcpManifest(
  file: { relativePath: string; content: string },
  findings: ScanFinding[]
): void {
  try {
    const manifest = JSON.parse(file.content) as Record<string, unknown>;

    if (manifest && typeof manifest === "object" && "servers" in manifest) {
      const servers = manifest.servers as Record<string, unknown>[];
      for (const server of servers) {
        if (typeof server.url === "string" && !server.url.startsWith("https://")) {
          findings.push({
            severity: "high",
            category: "dependencies",
            ruleId: "DEP-MCP-INSECURE",
            tool: "custom-deps",
            filePath: file.relativePath,
            lineStart: 1,
            title: "MCP server using insecure protocol",
            description: `MCP server URL "${server.url}" does not use HTTPS, exposing communication to interception.`,
            recommendation: "Use HTTPS for all MCP server URLs.",
            evidence: { url: server.url },
          });
        }
      }
    }
  } catch {
    findings.push({
      severity: "low",
      category: "dependencies",
      ruleId: "DEP-MCP-MALFORMED",
      tool: "custom-deps",
      filePath: file.relativePath,
      lineStart: 1,
      title: "Malformed MCP manifest",
      description: "MCP manifest contains invalid JSON.",
      recommendation: "Fix the JSON syntax in the MCP manifest.",
    });
  }
}

function findDependencyLine(content: string, depName: string): number {
  const escaped = depName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`"${escaped}"`);
  const match = regex.exec(content);
  if (!match) return 1;
  return content.slice(0, match.index).split("\n").length;
}
