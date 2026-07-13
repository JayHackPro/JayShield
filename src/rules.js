/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

/**
 * The signature ruleset.
 *
 * Each rule describes a well-documented malware technique, not a single
 * strain, so one rule catches a whole family and its copies. Signatures
 * like these are the same kind of defensive definitions that ClamAV,
 * Linux Malware Detect, and public YARA rule sets ship. They describe what
 * hostile code looks like so it can be found and removed. They are not
 * malware and cannot run.
 *
 * Fields:
 *   id          stable identifier, used in reports and in --ignore-rule
 *   name        short human title
 *   severity    critical | high | medium | low
 *   category    webshell | obfuscation | backdoor | exec | upload |
 *               injection | miner | skimmer | spam | test
 *   kinds       file kinds the rule applies to, or ["any"]
 *   pattern     a RegExp; the scanner reports the line of every match
 *   description one plain sentence on why this is suspicious
 *   references  further reading
 */

/** Map a file extension to a coarse "kind" the rules can target. */
export function kindForPath(filePath) {
  const lower = String(filePath).toLowerCase();
  const dot = lower.lastIndexOf(".");
  const ext = dot === -1 ? "" : lower.slice(dot + 1);
  switch (ext) {
    case "php":
    case "php3":
    case "php4":
    case "php5":
    case "php7":
    case "phtml":
    case "pht":
    case "phar":
      return "php";
    case "js":
    case "cjs":
    case "mjs":
    case "jsx":
    case "ts":
      return "js";
    case "html":
    case "htm":
    case "xhtml":
    case "shtml":
    case "tpl":
      return "html";
    case "asp":
    case "aspx":
    case "ashx":
      return "asp";
    case "py":
      return "python";
    case "pl":
    case "cgi":
      return "perl";
    case "sh":
    case "bash":
      return "shell";
    default:
      return "other";
  }
}

export const RULES = [
  // ----- PHP obfuscation: decode-then-run, the signature of almost every shell
  {
    id: "php.eval_decode",
    name: "Obfuscated eval of a decoded payload",
    severity: "critical",
    category: "obfuscation",
    kinds: ["php"],
    pattern: /\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|pack|rawurldecode|urldecode)\s*\(/i,
    description: "Code is hidden inside a decode call and run on the fly, the hallmark of a packed webshell.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.eval_user_input",
    name: "eval of raw request input",
    severity: "critical",
    category: "backdoor",
    kinds: ["php"],
    pattern: /\b(?:eval|assert)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i,
    description: "Runs whatever an attacker sends in the request as PHP code, a direct backdoor.",
    references: ["https://www.php.net/manual/en/function.eval.php"]
  },
  {
    id: "php.preg_replace_e",
    name: "preg_replace with the /e code modifier",
    severity: "critical",
    category: "backdoor",
    kinds: ["php"],
    pattern: /preg_replace\s*\(\s*(["'])(?:(?!\1).)*\/[a-z]*e[a-z]*\1/i,
    description: "The removed /e modifier executes the replacement as PHP, a classic remote code path.",
    references: ["https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php"]
  },
  {
    id: "php.create_function",
    name: "create_function dynamic code",
    severity: "high",
    category: "obfuscation",
    kinds: ["php"],
    pattern: /\bcreate_function\s*\(/i,
    description: "Builds and runs code from strings at runtime, removed from PHP and now seen almost only in backdoors.",
    references: ["https://www.php.net/manual/en/function.create-function.php"]
  },
  {
    id: "php.variable_function_input",
    name: "Variable function called from request input",
    severity: "critical",
    category: "backdoor",
    kinds: ["php"],
    pattern: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
    description: "Lets the request pick both the function to call and its arguments, a compact universal backdoor.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.exec_user_input",
    name: "Shell command built from request input",
    severity: "critical",
    category: "exec",
    kinds: ["php"],
    pattern: /\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:[^)]{0,60})?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/i,
    description: "Passes attacker-controlled text to the operating system shell, remote command execution.",
    references: ["https://owasp.org/www-community/attacks/Command_Injection"]
  },
  {
    id: "php.call_user_func_input",
    name: "Function name chosen by request input",
    severity: "critical",
    category: "backdoor",
    kinds: ["php"],
    pattern: /\bcall_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
    description: "Lets the request name the function to run, a compact backdoor.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.extract_input",
    name: "extract of request input",
    severity: "medium",
    category: "injection",
    kinds: ["php"],
    pattern: /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|SERVER|COOKIE)\b/i,
    description: "Turns request keys into local variables, which lets an attacker overwrite values the code trusts.",
    references: ["https://www.php.net/manual/en/function.extract.php"]
  },
  {
    id: "php.reverse_shell",
    name: "Reverse shell socket",
    severity: "critical",
    category: "backdoor",
    kinds: ["php", "python", "perl"],
    pattern: /\/bin\/(?:ba)?sh\s+-i|\bfsockopen\s*\([^)]{0,160}\)\s*;?\s*(?:\$\w+\s*=\s*)?(?:exec|shell_exec|proc_open|passthru|system|popen)\s*\(/i,
    description: "Opens a network socket and hands a shell back to the attacker.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.char_obfuscation",
    name: "Character-code string obfuscation",
    severity: "medium",
    category: "obfuscation",
    kinds: ["php"],
    pattern: /(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i,
    description: "A string is assembled from many chr() calls to hide what it spells.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.hex_obfuscation",
    name: "Long hex-escaped string",
    severity: "medium",
    category: "obfuscation",
    kinds: ["php", "js"],
    pattern: /(?:\\x[0-9a-f]{2}){12,}/i,
    description: "A long run of hex escapes is a common way to hide function names and payloads.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.global_variable_function",
    name: "Function call through GLOBALS or variable variable",
    severity: "high",
    category: "obfuscation",
    kinds: ["php"],
    pattern: /\$GLOBALS\s*\[[^\]]{1,30}\]\s*\(|\$\{\s*['"][^'"]+['"]\s*\}\s*\(/,
    description: "Calls a function whose name is hidden behind an array or variable lookup to dodge simple scans.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.remote_include_eval",
    name: "Remote payload fetched and run",
    severity: "critical",
    category: "backdoor",
    kinds: ["php"],
    pattern: /\b(?:eval|assert|include|require)(?:_once)?\s*\(\s*(?:file_get_contents|curl_exec|fopen)\s*\(/i,
    description: "Downloads code from elsewhere and runs it, so the real payload never sits on disk.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.upload_handler",
    name: "Unrestricted file upload handler",
    severity: "low",
    category: "upload",
    kinds: ["php"],
    pattern: /\bmove_uploaded_file\s*\(\s*\$_FILES\b/i,
    description: "Accepts an uploaded file. Worth confirming it blocks executable types and a safe folder.",
    references: ["https://owasp.org/www-community/attacks/Unrestricted_File_Upload"]
  },

  // ----- Known webshell family fingerprints
  {
    id: "shell.c99",
    name: "c99 webshell",
    severity: "critical",
    category: "webshell",
    kinds: ["php", "other"],
    pattern: /c99sh(?:ell)?|c99_|\$c99/i,
    description: "Fingerprint of the c99 webshell, a full remote file manager and command runner.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "shell.r57",
    name: "r57 webshell",
    severity: "critical",
    category: "webshell",
    kinds: ["php", "other"],
    pattern: /r57shell|\$r57|r57\.gen/i,
    description: "Fingerprint of the r57 webshell family.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "shell.wso",
    name: "WSO webshell",
    severity: "critical",
    category: "webshell",
    kinds: ["php", "other"],
    pattern: /WSO(?:hex)?|wso_ex|\$default_charset\s*=.*['"]FilesMan['"]/i,
    description: "Fingerprint of the WSO webshell, one of the most widely reused PHP shells.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "shell.b374k",
    name: "b374k webshell",
    severity: "critical",
    category: "webshell",
    kinds: ["php", "other"],
    pattern: /b374k|\$b374k|b374k\s*shell/i,
    description: "Fingerprint of the b374k webshell.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "shell.filesman",
    name: "FilesMan webshell action",
    severity: "high",
    category: "webshell",
    kinds: ["php", "other"],
    pattern: /['"]FilesMan['"]|actbox|actarj/,
    description: "The FilesMan action string is shared by a large family of copy-paste PHP shells.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "shell.generic_banner",
    name: "Webshell banner text",
    severity: "high",
    category: "webshell",
    kinds: ["php", "html", "other"],
    pattern: /Hacked\s*By\b|Defaced\s*by\b|Powered\s*by\s*[A-Za-z0-9]+\s*Shell\b|\bShell\s*by\s*[A-Za-z0-9]+|Mass\s*Deface/i,
    description: "Text seen on the pages that webshells and defacement kits print.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },
  {
    id: "php.password_gate",
    name: "Hardcoded password gate",
    severity: "high",
    category: "backdoor",
    kinds: ["php"],
    pattern: /\b(?:md5|sha1|crc32|hash)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b[^)]{0,40}\)\s*===?\s*(['"])[0-9a-f]{16,64}\1/i,
    description: "Hashes a request value and compares it to a fixed hash, the login check of a private backdoor.",
    references: ["https://owasp.org/www-community/attacks/Web_Shell"]
  },

  // ----- JavaScript and HTML injection
  {
    id: "js.document_write_unescape",
    name: "document.write of unescaped payload",
    severity: "high",
    category: "injection",
    kinds: ["js", "html"],
    pattern: /document\.write\s*\(\s*unescape\s*\(/i,
    description: "Writes hidden markup into the page at load, a long-running site-injection pattern.",
    references: ["https://owasp.org/www-community/attacks/xss/"]
  },
  {
    id: "js.eval_decode",
    name: "eval of a decoded string",
    severity: "high",
    category: "obfuscation",
    kinds: ["js", "html"],
    pattern: /\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/i,
    description: "Runs code that was decoded at the last moment to get past a quick read.",
    references: ["https://owasp.org/www-community/attacks/xss/"]
  },
  {
    id: "js.fromcharcode",
    name: "Long fromCharCode obfuscation",
    severity: "medium",
    category: "obfuscation",
    kinds: ["js", "html"],
    pattern: /String\.fromCharCode\s*\(\s*(?:\d{1,3}\s*,\s*){15,}/i,
    description: "A script assembled from many character codes to hide what it does.",
    references: ["https://owasp.org/www-community/attacks/xss/"]
  },
  {
    id: "js.hidden_iframe",
    name: "Hidden or zero-size iframe",
    severity: "high",
    category: "injection",
    kinds: ["html", "php", "js"],
    pattern: /<iframe\b[^>]*(?:(?:width|height)\s*=\s*["']?\s*[01]\b|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute[^"']*(?:top|left)\s*:\s*-?\d))/i,
    description: "An invisible iframe usually delivers malware or ad fraud to visitors without a trace on the page.",
    references: ["https://owasp.org/www-community/attacks/Content_Spoofing"]
  },
  {
    id: "js.cookie_exfil",
    name: "Cookie sent to an image or request",
    severity: "high",
    category: "skimmer",
    kinds: ["js", "html"],
    pattern: /(?:new\s+Image\s*\(\s*\)\s*\.\s*src|XMLHttpRequest|navigator\.sendBeacon)[^;\n]{0,80}document\.cookie/i,
    description: "Copies the visitor session cookie off to another server, a session-theft skimmer.",
    references: ["https://owasp.org/www-community/attacks/Session_hijacking_attack"]
  },
  {
    id: "js.location_decode",
    name: "Redirect to a decoded URL",
    severity: "medium",
    category: "injection",
    kinds: ["js", "html"],
    pattern: /(?:window\.)?location(?:\.href)?\s*=\s*(?:atob|unescape|decodeURIComponent)\s*\(/i,
    description: "Sends visitors to a hidden address, common in traffic-selling and phishing injections.",
    references: ["https://owasp.org/www-community/attacks/xss/"]
  },
  {
    id: "js.packer",
    name: "Packed eval(function(p,a,c,k,e",
    severity: "low",
    category: "obfuscation",
    kinds: ["js", "html"],
    pattern: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/i,
    description: "The Dean Edwards packer. Used by some real libraries, but also to hide injected scripts, so worth a look.",
    references: ["https://owasp.org/www-community/attacks/xss/"]
  },

  // ----- Cryptocurrency miners
  {
    id: "miner.browser",
    name: "In-browser cryptocurrency miner",
    severity: "high",
    category: "miner",
    kinds: ["js", "html", "php"],
    pattern: /coinhive|coin-hive|cryptonight|CoinImp|deepMiner|webminepool|crypto-loot|cryptoloot|minero\.cc|coinpot|jsecoin/i,
    description: "Loads a mining script that spends your visitors' devices and electricity for someone else.",
    references: ["https://www.cisa.gov/news-events/news/defending-against-cryptojacking"]
  },

  // ----- SEO and pharma spam injection
  {
    id: "spam.hidden_links",
    name: "Hidden link block",
    severity: "medium",
    category: "spam",
    kinds: ["html", "php"],
    pattern: /<(?:div|span)\b[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|position\s*:\s*absolute[^"']*left\s*:\s*-\d{3,})[^"']*["'][^>]*>\s*(?:<a\b[^>]*>[^<]*<\/a>\s*){2,}/i,
    description: "A block of links hidden from visitors but read by search engines, the shape of injected spam.",
    references: ["https://developers.google.com/search/docs/essentials/spam-policies"]
  },
  {
    id: "spam.pharma",
    name: "Pharma spam keywords in hidden markup",
    severity: "low",
    category: "spam",
    kinds: ["html", "php"],
    pattern: /(?:display\s*:\s*none|visibility\s*:\s*hidden)[^<]{0,120}(?:viagra|cialis|levitra|payday\s*loan|casino)\b/i,
    description: "Hidden pharmacy or gambling keywords, a sign of an SEO spam infection.",
    references: ["https://developers.google.com/search/docs/essentials/spam-policies"]
  },

  // ----- The industry-standard antivirus test file
  {
    id: "test.eicar",
    name: "EICAR antivirus test file",
    severity: "medium",
    category: "test",
    kinds: ["any"],
    pattern: /EICAR-STANDARD-ANTIVIRUS-TEST-FILE/,
    description: "The harmless EICAR test string. Not a threat, but every scanner should detect it, so this proves JayShield is working.",
    references: ["https://www.eicar.org/download-anti-malware-testfile/"]
  }
];

/** Compile a global-flagged copy of a rule pattern so we can find every hit. */
export function globalize(pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return new RegExp(pattern.source, flags);
}

/** Return the rules that apply to a given file kind, honoring an ignore set. */
export function rulesForKind(kind, ignore = new Set()) {
  return RULES.filter(
    (rule) =>
      !ignore.has(rule.id) &&
      (rule.kinds.includes("any") || rule.kinds.includes(kind))
  );
}
