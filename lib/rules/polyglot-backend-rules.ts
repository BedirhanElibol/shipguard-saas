/**
 * Polyglot Backend Security Rules (PHP, Java, C# / .NET, Ruby)
 * Addresses audit finding F-44 & F-45: Multi-language security analysis
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface PolyglotBackendRuleResult {
  findings: Finding[];
  logs: string[];
}

function extractSnippet(lines: string[], lineNum: number): string {
  const targetIdx = Math.max(0, lineNum - 1);
  const start = Math.max(0, targetIdx - 2);
  const end = Math.min(lines.length, targetIdx + 3);
  return lines.slice(start, end).join('\n');
}

export function evaluatePolyglotBackendRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): PolyglotBackendRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

  // Skip self-referential catalogs, mocks, and node_modules
  if (
    lowerPath.includes('data/catalogs/') ||
    lowerPath.includes('data/mockdata') ||
    lowerPath.includes('data/workspacefiles') ||
    lowerPath.includes('data/schema') ||
    lowerPath.includes('scratch/') ||
    lowerPath.includes('.agent/') ||
    lowerPath.includes('node_modules/') ||
    lowerPath.endsWith('.d.ts')
  ) {
    return { findings, logs };
  }

  const ts = new Date().toLocaleTimeString();

  // =========================================================================
  // 1. PHP SECURITY RULES (*.php, *.phtml, *.inc)
  // =========================================================================
  const isPhp = lowerPath.endsWith('.php') || lowerPath.endsWith('.phtml') || lowerPath.endsWith('.inc');
  if (isPhp) {
    // PHP-01: SQL Injection via unparameterized input concatenation
    const phpSqliRegex = /(?:mysql_query|mysqli_query|\$pdo->query|\$pdo->exec|\$db->query)\s*\(\s*(?:["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\.|\$[a-zA-Z0-9_]+\s*\.|\s*"\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*\$_(?:GET|POST|REQUEST|COOKIE))/i;
    const phpConcatSql = /\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\][\s\S]*?(?:SELECT|INSERT|UPDATE|DELETE)/i;

    if (phpSqliRegex.test(cleanContent) || (phpConcatSql.test(cleanContent) && /(?:query|exec)\s*\(/i.test(cleanContent))) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && (phpSqliRegex.test(l) || /\$_(?:GET|POST|REQUEST)/.test(l)));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `php-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18001,
        type: 'SECURITY',
        title: 'PHP-SEC-01: SQL Injection via Unparameterized Query Concatenation',
        severity: 'CRITICAL',
        category: 'SQL Injection',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'mysqli_query($conn, "SELECT ... " . $_GET["id"])',
        reproductionSteps: [
          `Scanned PHP source file at ${file.path}:${lineNum}.`,
          'Detected database query formatted with raw HTTP user parameters ($_GET/$_POST/$_REQUEST) without PDO prepared statements or parameterized binding.'
        ],
        remediationPrompt: 'Use PDO prepared statements with parameter binding: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute([":id" => $id]);',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: SQL Injection in ${file.path}:${lineNum}`);
    }

    // PHP-02: Local File Inclusion (LFI / Path Traversal)
    const phpLfiRegex = /(?:include|require|include_once|require_once)\s*\(?\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$[a-zA-Z0-9_]+\s*\.)/i;
    if (phpLfiRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && phpLfiRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `php-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18002,
        type: 'SECURITY',
        title: 'PHP-SEC-02: Local File Inclusion (LFI) via Dynamic include/require',
        severity: 'CRITICAL',
        category: 'Path Traversal',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'include($_GET["page"] . ".php")',
        reproductionSteps: [
          `Scanned PHP file inclusion logic at ${file.path}:${lineNum}.`,
          'Detected dynamic file inclusion using unvalidated user input, enabling arbitrary local file inclusion (LFI) and remote code execution.'
        ],
        remediationPrompt: 'Whitelist allowable file paths through a strict array lookup or avoid dynamic file inclusion completely.',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: Local File Inclusion in ${file.path}:${lineNum}`);
    }

    // PHP-03: Command Injection via shell execution
    const phpCmdRegex = /(?:exec|shell_exec|system|passthru|proc_open|popen)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|\$[a-zA-Z0-9_]+\s*\.)/i;
    if (phpCmdRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && phpCmdRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `php-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18003,
        type: 'SECURITY',
        title: 'PHP-SEC-03: OS Command Injection via shell_exec / system',
        severity: 'CRITICAL',
        category: 'Command Injection',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'shell_exec($_GET["cmd"])',
        reproductionSteps: [
          `Scanned system execution handlers in ${file.path}:${lineNum}.`,
          'Detected shell execution functions invoked with unsanitized HTTP input parameters.'
        ],
        remediationPrompt: 'Avoid system shell execution. If necessary, escape arguments with escapeshellarg() or escapeshellcmd().',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: Command Injection in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // 2. JAVA SECURITY RULES (*.java, *.jsp)
  // =========================================================================
  const isJava = lowerPath.endsWith('.java') || lowerPath.endsWith('.jsp');
  if (isJava) {
    // JAVA-01: Java SQL Injection via string concatenation
    const javaSqliRegex = /(?:executeQuery|executeUpdate|jdbcTemplate\.query|createQuery|createNativeQuery)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/i;
    if (javaSqliRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && javaSqliRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `java-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18011,
        type: 'SECURITY',
        title: 'JAVA-SEC-01: SQL Injection via String Concatenation in Statement Execution',
        severity: 'CRITICAL',
        category: 'SQL Injection',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'stmt.executeQuery("SELECT * FROM users WHERE id = " + id)',
        reproductionSteps: [
          `Scanned Java database query at ${file.path}:${lineNum}.`,
          'Detected JDBC Statement or JPA query constructed using string concatenation instead of PreparedStatement with parameterized query binding.'
        ],
        remediationPrompt: 'Use PreparedStatement with positional parameter markers (?): PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setString(1, id);',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [JAVA AUDIT] CRITICAL: Java SQL Injection in ${file.path}:${lineNum}`);
    }

    // JAVA-02: Hardcoded Secrets & Passwords in Source
    const javaHardcodedSecretRegex = /(?:String|char\[\])\s+(?:password|secretKey|apiKey|api_secret|auth_token)\s*=\s*["'][^"']{6,}["']/i;
    if (javaHardcodedSecretRegex.test(cleanContent) && !lowerPath.includes('test')) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && javaHardcodedSecretRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `java-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18012,
        type: 'SECURITY',
        title: 'JAVA-SEC-02: Hardcoded Password or Secret Key in Java Source Code',
        severity: 'HIGH',
        category: 'Hardcoded Secret',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'String password = "..."',
        reproductionSteps: [
          `Scanned Java source in ${file.path}:${lineNum}.`,
          'Detected plaintext password or authentication credential committed directly into source code.'
        ],
        remediationPrompt: 'Externalize credentials using environment variables (System.getenv("DB_PASSWORD")) or a secrets vault.',
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [JAVA AUDIT] HIGH: Hardcoded Credentials in ${file.path}:${lineNum}`);
    }

    // JAVA-03: Insecure Deserialization via ObjectInputStream
    const javaDeserializationRegex = /new\s+ObjectInputStream\b[\s\S]*?\.readObject\(\)/i;
    if (javaDeserializationRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && l.includes('readObject'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `java-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18013,
        type: 'SECURITY',
        title: 'JAVA-SEC-03: Unrestricted Java Deserialization via ObjectInputStream.readObject',
        severity: 'CRITICAL',
        category: 'Insecure Deserialization',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'ois.readObject()',
        reproductionSteps: [
          `Scanned serialization handlers in ${file.path}:${lineNum}.`,
          'Detected ObjectInputStream.readObject() deserializing untrusted binary streams without class filter verification, enabling remote code execution via gadget chains.'
        ],
        remediationPrompt: 'Implement ObjectInputFilter or replace Java native serialization with safe data interchange formats such as JSON or Protocol Buffers.',
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [JAVA AUDIT] CRITICAL: Java Insecure Deserialization in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // 3. C# / .NET SECURITY RULES (*.cs, *.cshtml, *.vb)
  // =========================================================================
  const isCSharp = lowerPath.endsWith('.cs') || lowerPath.endsWith('.cshtml') || lowerPath.endsWith('.vb');
  if (isCSharp) {
    // CS-01: C# SQL Injection via string interpolation or concatenation
    const csSqliRegex = /(?:new\s+SqlCommand|Database\.SqlQueryRaw|FromSqlRaw)\s*\(\s*(?:["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+|\$["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{)/i;
    if (csSqliRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && csSqliRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `cs-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18021,
        type: 'SECURITY',
        title: 'CS-SEC-01: C# SQL Injection via SqlCommand Interpolation / Concatenation',
        severity: 'CRITICAL',
        category: 'SQL Injection',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'new SqlCommand($"SELECT * FROM Users WHERE Id = {id}")',
        reproductionSteps: [
          `Scanned C# database command at ${file.path}:${lineNum}.`,
          'Detected dynamic SQL construction via string interpolation ($"...") or concatenation without SqlParameter parameterization.'
        ],
        remediationPrompt: 'Use parameterized SqlCommand with parameters: cmd.Parameters.AddWithValue("@id", id) or Entity Framework FromSqlInterpolated.',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [C# AUDIT] CRITICAL: C# SQL Injection in ${file.path}:${lineNum}`);
    }

    // CS-02: Weak Cryptographic Algorithms (MD5, SHA1, DES)
    const csWeakCryptoRegex = /(?:MD5\.Create|SHA1\.Create|DESCryptoServiceProvider|RC2CryptoServiceProvider|TripleDESCryptoServiceProvider)\s*\(/i;
    if (csWeakCryptoRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && csWeakCryptoRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `cs-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18022,
        type: 'SECURITY',
        title: 'CS-SEC-02: Cryptographically Broken Hash / Cipher Algorithm (MD5 / SHA1 / DES)',
        severity: 'HIGH',
        category: 'Cryptographic Weakness',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'MD5.Create()',
        reproductionSteps: [
          `Scanned cryptographic primitives at ${file.path}:${lineNum}.`,
          'Detected deprecated, collision-vulnerable cryptographic algorithm (MD5/SHA1/DES).'
        ],
        remediationPrompt: 'Upgrade to collision-resistant hash functions: SHA256.Create() or SHA512.Create(), and Aes.Create() for symmetric encryption.',
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [C# AUDIT] HIGH: Weak Cryptography in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // 4. RUBY / RAILS SECURITY RULES (*.rb, *.erb, *.rake)
  // =========================================================================
  const isRuby = lowerPath.endsWith('.rb') || lowerPath.endsWith('.erb') || lowerPath.endsWith('.rake');
  if (isRuby) {
    // RUBY-01: Ruby ActiveRecord SQL Injection
    const rubySqliRegex = /(?:find_by_sql|\.where|\.order|\.having|\.pluck)\s*\(\s*(?:["'][^"']*\b(?:SELECT|FROM|WHERE|ORDER|GROUP)\b[^"']*#\{|["'][^"']*#\{params\[)/i;
    if (rubySqliRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && rubySqliRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `ruby-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18031,
        type: 'SECURITY',
        title: 'RUBY-SEC-01: Ruby on Rails SQL Injection in ActiveRecord Query Interpolation',
        severity: 'CRITICAL',
        category: 'SQL Injection',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'User.where("name = #{params[:name]}")',
        reproductionSteps: [
          `Scanned ActiveRecord queries at ${file.path}:${lineNum}.`,
          'Detected direct Ruby string interpolation (#{}) inside ActiveRecord query fragments, bypassing SQL escaping.'
        ],
        remediationPrompt: 'Use parameterized array syntax: User.where("name = ?", params[:name]) or hash conditions: User.where(name: params[:name]).',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [RUBY AUDIT] CRITICAL: Ruby SQL Injection in ${file.path}:${lineNum}`);
    }

    // RUBY-02: Ruby Mass Assignment via params.permit!
    const rubyMassAssignmentRegex = /params(?:\[[^\]]+\]|\.[a-zA-Z0-9_]+(?:\([^)]*\))?)*\.permit!(?:\s|\(|$|;)/i;
    if (rubyMassAssignmentRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && rubyMassAssignmentRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `ruby-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18032,
        type: 'SECURITY',
        title: 'RUBY-SEC-02: Insecure Mass Assignment via params.permit!',
        severity: 'HIGH',
        category: 'Mass Assignment',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'params.require(:user).permit!',
        reproductionSteps: [
          `Scanned controller action in ${file.path}:${lineNum}.`,
          'Detected params.permit! which completely disables Strong Parameters, allowing attackers to overwrite protected model attributes (e.g. role, admin, balance).'
        ],
        remediationPrompt: 'Explicitly whitelist required model attributes: params.require(:user).permit(:username, :email). Never call permit! on untrusted parameters.',
        status: 'OPEN',
        owner: 'Backend Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [RUBY AUDIT] HIGH: Ruby Mass Assignment in ${file.path}:${lineNum}`);
    }

    // RUBY-03: Ruby Remote Code Execution via eval / Kernel.system
    const rubyEvalRegex = /(?:eval|Kernel\.eval|system|Kernel\.system|`)\s*\(\s*(?:params\[|#\{params\[)/i;
    if (rubyEvalRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && rubyEvalRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = extractSnippet(lines, lineNum);

      findings.push({
        id: `ruby-${Date.now()}-${findingCounter.count++}`,
        ruleId: 18033,
        type: 'SECURITY',
        title: 'RUBY-SEC-03: Remote Code Execution via eval with Unsanitized Parameters',
        severity: 'CRITICAL',
        category: 'Remote Code Execution',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'eval(params[:cmd])',
        reproductionSteps: [
          `Scanned dynamic evaluation handlers at ${file.path}:${lineNum}.`,
          'Detected eval() or system() invoked directly with untrusted request parameters.'
        ],
        remediationPrompt: 'Remove dynamic code evaluation. Use static condition trees or safe domain-specific dispatchers.',
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] 🔒 [RUBY AUDIT] CRITICAL: Ruby Remote Code Execution in ${file.path}:${lineNum}`);
    }
  }

  return { findings, logs };
}
