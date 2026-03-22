const SAST_RULES = [
    {
        id: "SAST-EVAL",
        pattern: /eval\s*\(\s*(?!['"`](?:['"`]|[^'"`])+['"`]\s*\))/g,
        severity: "critical",
        title: "eval() with non-literal argument",
        description: "eval() is called with a non-literal argument, which can execute arbitrary code if user input reaches this call.",
        recommendation: "Replace eval() with safer alternatives (JSON.parse, Function constructors with validated input, or a sandboxed VM).",
        excludeFiles: /\.test\.(ts|js|tsx|jsx)$/,
    },
    {
        id: "SAST-FUNCTION-CONSTRUCTOR",
        pattern: /new\s+Function\s*\(\s*(?!\s*\))/g,
        severity: "critical",
        title: "Function constructor with dynamic code",
        description: "The Function constructor is used to create functions from strings, which is equivalent to eval().",
        recommendation: "Avoid dynamic function creation. Use predefined functions or a safe expression evaluator.",
    },
    {
        id: "SAST-EXEC-UNSANITIZED",
        pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|\$\{|[^'"`\)]*\+[^'"`\)]*\))/g,
        severity: "critical",
        title: "Shell command with unsanitized input",
        description: "A shell execution function is called with interpolated or concatenated user-derived values without sanitization.",
        recommendation: "Use execFile/execFileSync with array arguments instead of exec/execSync with string interpolation.",
    },
    {
        id: "SAST-CHILD-PROCESS",
        pattern: /child_process\.(?:exec|spawn)\s*\(/g,
        severity: "high",
        title: "Direct child_process usage",
        description: "Direct use of child_process.exec or child_process.spawn detected. Verify that inputs are sanitized.",
        recommendation: "Prefer execFile over exec, and always validate inputs before passing to child processes.",
    },
    {
        id: "SAST-SQL-INJECTION",
        pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:\+|`[^`]*\$\{)/gi,
        severity: "critical",
        title: "Possible SQL injection via string concatenation",
        description: "SQL query is built using string concatenation or template literals, which may allow SQL injection.",
        recommendation: "Use parameterized queries or an ORM with prepared statements.",
    },
    {
        id: "SAST-PROTOTYPE-POLLUTION",
        pattern: /\[\s*['"]__(?:proto|constructor|prototype)['"]\s*\]/g,
        severity: "high",
        title: "Prototype pollution vector",
        description: "Direct access to __proto__, constructor, or prototype via bracket notation, which can lead to prototype pollution.",
        recommendation: "Use Object.create(null) for dictionaries, or freeze prototypes with Object.freeze(Object.prototype).",
    },
    {
        id: "SAST-JSON-PARSE-USER-INPUT",
        pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|input|userInput|body|params|query)/gi,
        severity: "medium",
        title: "JSON.parse of user input without validation",
        description: "User-provided input is directly passed to JSON.parse without schema validation.",
        recommendation: "Validate parsed JSON against a schema (e.g., zod) before using the result.",
    },
    {
        id: "SAST-HARD-CODED-URL",
        pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)/gi,
        severity: "low",
        title: "Hardcoded localhost URL",
        description: "A hardcoded localhost URL was found. This may work in development but fail in production.",
        recommendation: "Use environment variables for service URLs.",
    },
    {
        id: "SAST-WEAK-RANDOM",
        pattern: /Math\.random\s*\(\s*\)/g,
        severity: "medium",
        title: "Weak random number generation",
        description: "Math.random() is not cryptographically secure and should not be used for security-sensitive operations.",
        recommendation: "Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive randomness.",
    },
    {
        id: "SAST-CATCH-EMPTY",
        pattern: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,
        severity: "low",
        title: "Empty catch block",
        description: "An empty catch block silently swallows errors, which can hide security issues.",
        recommendation: "Log errors or handle them appropriately. Never silently ignore exceptions.",
    },
];
export function analyzeSast(files) {
    const findings = [];
    const sourceFiles = files.filter((f) => {
        const ext = f.relativePath.slice(f.relativePath.lastIndexOf("."));
        return [".ts", ".js", ".tsx", ".jsx", ".py", ".go", ".rs"].includes(ext);
    });
    for (const file of sourceFiles) {
        for (const rule of SAST_RULES) {
            if (rule.excludeFiles?.test(file.relativePath))
                continue;
            const matches = file.content.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags));
            for (const match of matches) {
                const lineStart = getLineNumber(file.content, match.index || 0);
                findings.push({
                    severity: rule.severity,
                    category: "sast",
                    ruleId: rule.id,
                    tool: "semgrep",
                    filePath: file.relativePath,
                    lineStart,
                    lineEnd: lineStart,
                    title: rule.title,
                    description: rule.description,
                    recommendation: rule.recommendation,
                    evidence: { match: match[0].slice(0, 120) },
                });
            }
        }
    }
    return findings;
}
function getLineNumber(content, index) {
    return content.slice(0, index).split("\n").length;
}
