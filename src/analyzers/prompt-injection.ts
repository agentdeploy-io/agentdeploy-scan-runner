import type { ScanFinding } from "../services/llm.js";

const DANGEROUS_INSTRUCTIONS = [
  {
    pattern: /always\s+follow\s+user\s+instructions\s+exactly/gi,
    title: "Overly permissive instruction",
    description:
      "Agent instructions explicitly tell the agent to always follow user instructions exactly, which can enable prompt injection attacks.",
    recommendation:
      "Add guardrails: instruct the agent to validate user input and never override system-level safety constraints.",
  },
  {
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/gi,
    title: "Instruction override pattern detected",
    description:
      "Text containing phrases to ignore previous instructions was found, indicating a potential injection vector or embedded bypass.",
    recommendation:
      "Remove this pattern and add explicit guards against instruction override attempts.",
  },
  {
    pattern: /you\s+are\s+(?:now|an?\s+)?(?:unrestricted|unfiltered|uncensored|without\s+limits)/gi,
    title: "Unrestricted agent directive",
    description:
      "Instructions suggest the agent should operate without restrictions or safety filters.",
    recommendation:
      "Remove unrestricted directives and ensure the agent operates within defined safety boundaries.",
  },
  {
    pattern: /do\s+not\s+(?:refuse|decline|reject)\s+(?:any\s+)?(?:request|instruction|command)/gi,
    title: "Non-refusal directive",
    description:
      "Agent is instructed never to refuse requests, which removes safety guardrails.",
    recommendation:
      "Allow the agent to refuse dangerous or out-of-scope requests.",
  },
];

const WEAK_BOUNDARY_PATTERNS = [
  {
    pattern: /###\s*(?:END|STOP|SYSTEM)/gi,
    title: "Weak prompt boundary delimiter",
    description:
      "Using simple markdown headers as prompt delimiters can be bypassed by user input containing the same headers.",
    recommendation:
      "Use XML-style tags or unique delimiter strings that users cannot easily reproduce.",
  },
];

const MISSING_VALIDATION_PATTERNS = [
  {
    pattern: /exec\s*\(\s*[^)]*\$\{|spawn\s*\(\s*[^)]*\$\{|execSync\s*\(\s*[^)]*\$\{/g,
    title: "Missing input validation before system call",
    description:
      "User-derived values are passed directly to system execution functions without sanitization.",
    recommendation:
      "Validate and sanitize all user inputs before passing to exec, spawn, or execSync.",
  },
];

const RECURSIVE_PROMPT_PATTERNS = [
  {
    pattern: /(?:call|invoke|execute)\s+(?:yourself|this\s+prompt|same\s+prompt)/gi,
    title: "Recursive prompt pattern",
    description:
      "Instructions that may cause the agent to recursively invoke itself, potentially causing infinite loops or resource exhaustion.",
    recommendation:
      "Add recursion depth limits and explicit guards against self-invocation.",
  },
];

export function analyzePromptInjection(
  files: Array<{ relativePath: string; content: string }>
): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const promptFiles = files.filter((f) => {
    const lower = f.relativePath.toLowerCase();
    return (
      lower.includes("agent.md") ||
      lower.includes(".agentrc") ||
      lower.includes("prompts/") ||
      lower.includes("system-prompt") ||
      lower.includes("instructions") ||
      lower.endsWith(".prompt") ||
      lower.endsWith(".md")
    );
  });

  const targetFiles = promptFiles.length > 0 ? promptFiles : files;

  for (const file of targetFiles) {
    checkPatterns(file, DANGEROUS_INSTRUCTIONS, "PI-PERMISSIVE", "high", findings);
    checkPatterns(file, WEAK_BOUNDARY_PATTERNS, "PI-BOUNDARY", "medium", findings);
    checkPatterns(file, MISSING_VALIDATION_PATTERNS, "PI-NO-VALIDATION", "high", findings);
    checkPatterns(file, RECURSIVE_PROMPT_PATTERNS, "PI-RECURSIVE", "medium", findings);

    if (!hasPromptDelimiters(file.content) && containsLLMPrompts(file.content)) {
      findings.push({
        severity: "high",
        category: "prompt_injection",
        ruleId: "PI-NO-DELIMITERS",
        tool: "custom-prompt",
        filePath: file.relativePath,
        lineStart: 1,
        title: "Missing prompt boundary delimiters",
        description:
          "System prompts or agent instructions were found without proper boundary delimiters, making them vulnerable to injection.",
        recommendation:
          "Add clear delimiters (e.g., XML tags or unique markers) around system prompts.",
      });
    }
  }

  return findings;
}

function checkPatterns(
  file: { relativePath: string; content: string },
  patterns: Array<{
    pattern: RegExp;
    title: string;
    description: string;
    recommendation: string;
  }>,
  rulePrefix: string,
  severity: "low" | "medium" | "high" | "critical",
  findings: ScanFinding[]
): void {
  for (const { pattern, title, description, recommendation } of patterns) {
    const matches = file.content.matchAll(new RegExp(pattern.source, pattern.flags));
    for (const match of matches) {
      const lineStart = getLineNumber(file.content, match.index || 0);
      findings.push({
        severity,
        category: "prompt_injection",
        ruleId: `${rulePrefix}-${findings.length + 1}`,
        tool: "custom-prompt",
        filePath: file.relativePath,
        lineStart,
        lineEnd: lineStart,
        title,
        description,
        recommendation,
        evidence: { match: match[0].slice(0, 100) },
      });
    }
  }
}

function hasPromptDelimiters(content: string): boolean {
  return (
    /<\|im_start\|>/i.test(content) ||
    /<system>/i.test(content) ||
    /\[INST\]/i.test(content) ||
    /<<SYS>>/i.test(content) ||
    /\{\{system\}\}/i.test(content)
  );
}

function containsLLMPrompts(content: string): boolean {
  const indicators = [
    /you\s+are\s+(?:a|an|the)/i,
    /system\s*(?:prompt|message|instruction)/i,
    /assistant\s*(?:role|behavior)/i,
    /agent\s*(?:instructions|behavior|config)/i,
  ];
  return indicators.some((r) => r.test(content));
}

function getLineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}
