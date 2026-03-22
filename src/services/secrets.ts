import { logger } from "../logger.js";
import type { ScanFinding } from "./llm.js";

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  description: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "SECRET-AWS-KEY",
    name: "AWS Access Key",
    regex: /(?:^|[^A-Za-z0-9\/+=])(?:AKIA|ASIA)[0-9A-Z]{16}(?:[^A-Za-z0-9\/+=]|$)/g,
    severity: "critical",
    description: "AWS access key detected",
  },
  {
    id: "SECRET-OPENAI-KEY",
    name: "OpenAI API Key",
    regex: /sk-[A-Za-z0-9]{20,}(?![A-Za-z0-9]*your|key|here|placeholder)/g,
    severity: "critical",
    description: "OpenAI API key detected",
  },
  {
    id: "SECRET-GITHUB-TOKEN",
    name: "GitHub Token",
    regex: /ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9]*your|key|here|placeholder)/g,
    severity: "critical",
    description: "GitHub personal access token detected",
  },
  {
    id: "SECRET-GITHUB-OAUTH",
    name: "GitHub OAuth Token",
    regex: /gho_[A-Za-z0-9]{36}/g,
    severity: "high",
    description: "GitHub OAuth token detected",
  },
  {
    id: "SECRET-SLACK-TOKEN",
    name: "Slack Token",
    regex: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: "high",
    description: "Slack token detected",
  },
  {
    id: "SECRET-PRIVATE-KEY",
    name: "Private Key",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
    description: "Private key detected",
  },
  {
    id: "SECRET-JWT-SECRET",
    name: "JWT Secret",
    regex: /(?:JWT_SECRET|jwt_secret|jwtSecret)\s*[:=]\s*['"`][^'"`\s]{16,}['"`]/gi,
    severity: "high",
    description: "JWT secret detected",
  },
  {
    id: "SECRET-DATABASE-URL",
    name: "Database Connection String",
    regex: /(?:postgres|mysql|mongodb):\/\/[^'"`\s]+:[^'"`\s]+@[^'"`\s]+/gi,
    severity: "critical",
    description: "Database connection string with credentials detected",
  },
  {
    id: "SECRET-GENERIC-API-KEY",
    name: "Generic API Key Assignment",
    regex: /(?:API_KEY|api_key|apiKey|SECRET_KEY|secret_key|secretKey|ACCESS_TOKEN|accessToken)\s*[:=]\s*['"`](?!sk-your|YOUR_|REPLACE_|CHANGE_|TODO|xxx)[A-Za-z0-9_\-/.]{16,}['"`]/gi,
    severity: "high",
    description: "API key or secret assigned to non-placeholder value",
  },
  {
    id: "SECRET-STRIPE-KEY",
    name: "Stripe API Key",
    regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/g,
    severity: "critical",
    description: "Stripe API key detected",
  },
];

const PLACEHOLDER_PATTERNS = [
  /your[-_]?key/i,
  /replace[-_]?me/i,
  /change[-_]?me/i,
  /TODO/i,
  /xxx+/i,
  /placeholder/i,
  /example/i,
  /dummy/i,
  /sample/i,
];

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value));
}

function calculateEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

export function scanForSecrets(
  files: Array<{ relativePath: string; content: string }>
): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const file of files) {
    for (const pattern of SECRET_PATTERNS) {
      const matches = file.content.matchAll(pattern.regex);

      for (const match of matches) {
        const matchedText = match[0];

        if (isPlaceholder(matchedText)) continue;

        const lineStart = getLineNumber(file.content, match.index || 0);

        findings.push({
          severity: pattern.severity,
          category: "secrets",
          ruleId: pattern.id,
          tool: "custom-secrets",
          filePath: file.relativePath,
          lineStart,
          lineEnd: lineStart,
          title: pattern.name,
          description: pattern.description,
          recommendation: `Remove hardcoded secret from ${file.relativePath} and use environment variables instead.`,
          evidence: { match: matchedText.slice(0, 20) + "..." },
        });
      }
    }

    const highEntropyStrings = findHighEntropyStrings(file.content);
    for (const { value, index } of highEntropyStrings) {
      if (isPlaceholder(value)) continue;

      const lineStart = getLineNumber(file.content, index);
      findings.push({
        severity: "medium",
        category: "secrets",
        ruleId: "SECRET-HIGH-ENTROPY",
        tool: "custom-secrets",
        filePath: file.relativePath,
        lineStart,
        lineEnd: lineStart,
        title: "High-entropy string detected",
        description:
          "A string with high randomness was found, which may be a hardcoded secret or token.",
        recommendation:
          "Review this string. If it is a secret, move it to environment variables.",
        evidence: { value: value.slice(0, 20) + "...", entropy: calculateEntropy(value).toFixed(2) },
      });
    }
  }

  logger.info({ count: findings.length }, "Secret scan complete");
  return findings;
}

function findHighEntropyStrings(
  content: string
): Array<{ value: string; index: number }> {
  const results: Array<{ value: string; index: number }> = [];
  const stringRegex = /['"`]([A-Za-z0-9+/=_\-]{20,})['"`]/g;

  let match;
  while ((match = stringRegex.exec(content)) !== null) {
    const value = match[1];
    if (calculateEntropy(value) > 4.5) {
      results.push({ value, index: match.index });
    }
  }

  return results;
}

function getLineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}
