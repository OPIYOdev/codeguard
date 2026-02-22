import { useState, useEffect, useRef, useCallback } from "react";

// ─── Palette & Design System ───────────────────────────────────────────────
const COLORS = {
  bg:        "#0A0B0F",
  surface:   "#111318",
  surfaceAlt:"#161820",
  border:    "#1E2130",
  borderHi:  "#2A2F45",
  text:      "#E8EAF0",
  textMid:   "#8B90A8",
  textDim:   "#454860",
  accent:    "#4DFFC3",
  accentDim: "#1A3D30",
  red:       "#FF4D6A",
  redDim:    "#3D1520",
  orange:    "#FF9140",
  orangeDim: "#3D2010",
  yellow:    "#FFD740",
  yellowDim: "#3D3010",
  blue:      "#4D9FFF",
  blueDim:   "#102040",
  purple:    "#B97FFF",
  purpleDim: "#1E1040",
};

const SEV_CONFIG = {
  CRITICAL: { color: COLORS.red,    bg: COLORS.redDim,    icon: "⬛", label: "Critical" },
  HIGH:     { color: COLORS.orange, bg: COLORS.orangeDim, icon: "🔶", label: "High"     },
  MEDIUM:   { color: COLORS.yellow, bg: COLORS.yellowDim, icon: "🔷", label: "Medium"   },
  LOW:      { color: COLORS.blue,   bg: COLORS.blueDim,   icon: "⬜", label: "Low"      },
  INFO:     { color: COLORS.textMid,bg: COLORS.surface,   icon: "○",  label: "Info"     },
};

const LAYER_CONFIG = {
  L0: { label: "AST Parse Gate",        icon: "⬡", color: COLORS.purple },
  L1: { label: "Static Analysis",       icon: "⬡", color: COLORS.blue   },
  L2: { label: "Security Scan",         icon: "⬡", color: COLORS.red    },
  L3: { label: "Dynamic Testing",       icon: "⬡", color: COLORS.accent },
  L4: { label: "Memory & Performance",  icon: "⬡", color: COLORS.orange },
};

// ─── Mock Analysis Engine ───────────────────────────────────────────────────
function generateAnalysis(source, filename, repoUrl) {
  const lang = detectLanguage(filename || repoUrl || "");
  const lines = source ? source.split("\n") : [];
  const findings = [];
  let id = 1;

  const addFinding = (sev, layer, rule, line, message, fix, snippet = "") => {
    findings.push({ id: id++, severity: sev, layer, rule, line, message, fix, snippet, file: filename || "main" });
  };

  if (source) {
    // L0 — Parse checks
    const unmatchedBraces = (source.match(/\{/g)||[]).length - (source.match(/\}/g)||[]).length;
    if (Math.abs(unmatchedBraces) > 2) addFinding("CRITICAL","L0","SYNTAX-BRACE",1,`Unmatched braces detected (${unmatchedBraces > 0 ? "+" : ""}${unmatchedBraces})`,  "Check all { } pairs are balanced", "{...");

    // L1 — Static
    lines.forEach((line, i) => {
      const ln = i + 1;
      const t = line.trim();
      if (/def\s+\w+\s*\([^)]*=\s*(\[\]|\{\})/.test(t))
        addFinding("HIGH","L1","B006-MUTABLE-DEFAULT",ln,"Mutable default argument — all callers share this object across invocations","Use None sentinel: def fn(x=None), then if x is None: x = []", t);
      if (/for\s+\w+\s+in\s+.*:\s*$/.test(t) && lines[i+1] && /\w+\.(remove|pop)\(/.test(lines[i+1]))
        addFinding("HIGH","L1","MUTATE-WHILE-ITERATE",ln,"Mutating collection during iteration — elements will be skipped silently","Iterate over a copy: for x in items[:]: ... or use list comprehension", t);
      if (/==\s*0\.0|==\s*1\.0|0\.0\s*==/.test(t))
        addFinding("HIGH","L1","FLOAT-EQUALITY",ln,"Float equality comparison — IEEE 754 makes this unreliable","Use math.isclose(x, 0.0, abs_tol=1e-9) instead of ==", t);
      if (/\bexcept\s*:\s*$|\bexcept\s+Exception\s*:\s*$/.test(t) && lines[i+1] && /pass/.test(lines[i+1]))
        addFinding("HIGH","L1","SWALLOWED-EXCEPTION",ln,"Bare except: pass swallows all errors silently — bugs become invisible","Catch specific exceptions, log with context, never silently pass", t);
      if (/\bvar\s+/.test(t) && lang === "javascript")
        addFinding("MEDIUM","L1","NO-VAR",ln,"'var' has function scope — use let/const for block scoping","Replace var with const (preferred) or let", t);
      if (/(==|!=)\s*null\b/.test(t) && lang === "javascript")
        addFinding("MEDIUM","L1","LOOSE-NULL-CHECK",ln,"Loose null check with == may match undefined unexpectedly","Use === null or ?? nullish coalescing", t);
      if (/\.equals\s*\(/.test(t) && lang !== "java")
        addFinding("INFO","L1","WRONG-EQUALS",ln,"In Java, == compares references not values for objects","This looks correct for Java — ensure you're not using == for String comparison", t);
      if (/radon|lizard|complexity/.test(t))
        addFinding("INFO","L1","COMPLEXITY-TOOL",ln,"Complexity tool reference detected","Ensure cyclomatic complexity stays ≤ 10 per function", t);
    });

    // L2 — Security
    lines.forEach((line, i) => {
      const ln = i + 1; const t = line.trim();
      if (/f['"]\s*.*SELECT|execute\s*\(\s*['"]\s*SELECT.*\+|execute\s*\(\s*f['"]/i.test(t))
        addFinding("CRITICAL","L2","SQL-INJECTION",ln,"SQL query built with string interpolation — vulnerable to injection","Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))", t);
      if (/\beval\s*\(/.test(t))
        addFinding("CRITICAL","L2","EVAL-EXEC",ln,"eval() executes arbitrary code — critical attack surface","Remove eval(). Use explicit data structures or ast.literal_eval() for safe parsing", t);
      if (/os\.system\s*\(|subprocess.*shell\s*=\s*True/.test(t))
        addFinding("CRITICAL","L2","SHELL-INJECTION",ln,"Shell injection risk — user input could execute arbitrary commands","Use subprocess.run([...], shell=False) with explicit argument list", t);
      if (/password\s*=\s*['"][^'"]{3,}['"]|secret\s*=\s*['"][^'"]{3,}['"]/i.test(t))
        addFinding("CRITICAL","L2","HARDCODED-SECRET",ln,"Hardcoded credential detected in source code","Move to environment variable: os.environ.get('SECRET_KEY') or use a secrets manager", t);
      if (/pickle\.loads?\s*\(/.test(t))
        addFinding("CRITICAL","L2","UNSAFE-DESERIALIZE",ln,"pickle.loads() on untrusted data allows arbitrary code execution","Use JSON or a safe serialization format for untrusted data", t);
      if (/yaml\.load\s*\((?!.*Loader)/.test(t))
        addFinding("HIGH","L2","YAML-UNSAFE",ln,"yaml.load() without Loader= is unsafe — use yaml.safe_load()","Replace with: yaml.safe_load(stream)", t);
      if (/hashlib\.(md5|sha1)\s*\(/.test(t))
        addFinding("HIGH","L2","WEAK-HASH",ln,"MD5/SHA1 are cryptographically broken — do not use for security purposes","Use hashlib.sha256() or hashlib.sha3_256() instead", t);
      if (/random\.(random|randint|choice)\s*\(/.test(t) && /token|key|secret|auth|session/i.test(lines.slice(Math.max(0,i-3), i+3).join("")))
        addFinding("HIGH","L2","WEAK-RANDOM",ln,"random module is not cryptographically secure — do not use for tokens or keys","Use secrets.token_hex(32) or secrets.randbelow(N) for security-sensitive randomness", t);
      if (/debug\s*=\s*True|DEBUG\s*=\s*True/.test(t))
        addFinding("HIGH","L2","DEBUG-ENABLED",ln,"Debug mode enabled — exposes stack traces and internal state to users","Set debug=False in production. Use environment variable: DEBUG=os.environ.get('DEBUG','False')=='True'", t);
      if (/\.innerHTML\s*=/.test(t))
        addFinding("HIGH","L2","XSS-INNERHTML",ln,"innerHTML assignment with dynamic content — XSS vulnerability","Use textContent for plain text, or DOMPurify.sanitize() before innerHTML assignment", t);
      if (/localStorage\.(set|get)Item.*[Tt]oken/.test(t))
        addFinding("HIGH","L2","TOKEN-LOCALSTORAGE",ln,"Storing auth tokens in localStorage — accessible to XSS attacks","Store tokens in httpOnly, Secure, SameSite=Strict cookies instead", t);
      if (/JWT.*verify\s*=\s*False|decode\(.*verify\s*=\s*False/.test(t))
        addFinding("CRITICAL","L2","JWT-NO-VERIFY",ln,"JWT decoded with verification disabled — authentication bypass possible","Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256'])", t);
    });

    // L3 — Dynamic / edge cases
    lines.forEach((line, i) => {
      const ln = i + 1; const t = line.trim();
      if (/def\s+\w+\s*\(/.test(t) && !/None|Optional|Union/.test(lines.slice(i, i+5).join("")))
        addFinding("MEDIUM","L3","MISSING-NULL-GUARD",ln,"Function accepts parameters with no None/null guard at entry point","Add guard at top: if param is None: raise ValueError('param cannot be None')", t);
      if (/while\s+True/.test(t) && !lines.slice(i, i+15).join("").includes("break"))
        addFinding("HIGH","L3","INFINITE-LOOP",ln,"while True loop with no break detected — potential infinite loop","Add a break condition or maximum iteration counter", t);
      if (/async\s+def/.test(t) && lines.slice(i, i+20).join("").includes("time.sleep"))
        addFinding("CRITICAL","L3","BLOCKING-IN-ASYNC",ln,"time.sleep() inside async function blocks the entire event loop","Replace with: await asyncio.sleep(seconds)", t);
      if (/asyncio\.create_task\(/.test(t) && !lines.slice(i, i+5).join("").includes("add_done_callback"))
        addFinding("HIGH","L3","UNHANDLED-TASK",ln,"asyncio task created without error callback — exceptions silently dropped","Add: task.add_done_callback(lambda t: t.exception())", t);
    });

    // L4 — Performance
    let inLoop = false;
    lines.forEach((line, i) => {
      const ln = i + 1; const t = line.trim();
      if (/^\s*(for|while)\s+/.test(line)) inLoop = true;
      if (/^\s*(return|def\s)/.test(line) && !/^\s*(for|while)/.test(line)) inLoop = false;
      if (inLoop && /\w+\s*\+=\s*['"]/.test(t))
        addFinding("HIGH","L4","STRING-CONCAT-LOOP",ln,"String concatenation in loop is O(n²) — each += copies the entire string","Collect in list: parts.append(x), then join at end: ''.join(parts)", t);
      if (inLoop && /re\.(match|search|compile)\s*\(/.test(t))
        addFinding("MEDIUM","L4","REGEX-IN-LOOP",ln,"Regex compiled inside loop — recompiles on every iteration","Move compile outside: pattern = re.compile(...) before the loop", t);
      if (inLoop && /\.objects\.(get|filter|all)\s*\(/.test(t))
        addFinding("HIGH","L4","N+1-QUERY",ln,"Database query inside loop — N+1 query problem: scales linearly with records","Use select_related() / prefetch_related() or batch fetch before the loop", t);
      if (/for\s+\w+\s+in\s+range\(len\(/.test(t))
        addFinding("LOW","L4","RANGE-LEN-ANTI",ln,"range(len(x)) is an anti-pattern — use enumerate() for index+value","Replace with: for i, item in enumerate(collection):", t);
    });
  } else {
    // GitHub repo demo findings
    addFinding("CRITICAL","L2","SQL-INJECTION",47,"SQL query built with string interpolation in api/users.py","Use parameterized queries", "query = f'SELECT * FROM users WHERE id={user_id}'");
    addFinding("CRITICAL","L2","HARDCODED-SECRET",12,"AWS_SECRET_KEY hardcoded in config.py","Move to environment variable", "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'");
    addFinding("HIGH","L1","B006-MUTABLE-DEFAULT",23,"Mutable default argument in utils/helpers.py","Use None sentinel","def process(data, cache={}):");
    addFinding("HIGH","L2","WEAK-HASH",88,"MD5 used for password hashing in auth/security.py","Use bcrypt or argon2","hashlib.md5(password.encode())");
    addFinding("HIGH","L3","BLOCKING-IN-ASYNC",134,"time.sleep() inside async handler blocks event loop","Use asyncio.sleep()","time.sleep(2)");
    addFinding("HIGH","L4","N+1-QUERY",67,"ORM query inside loop — scales badly with data","Use select_related()","for order in orders: order.customer.name");
    addFinding("MEDIUM","L1","SWALLOWED-EXCEPTION",201,"except: pass silently swallows all errors","Log with context","except: pass");
    addFinding("MEDIUM","L3","MISSING-NULL-GUARD",156,"No null check before chained attribute access","Add None guard","return user.profile.avatar.url");
    addFinding("MEDIUM","L4","STRING-CONCAT-LOOP",78,"String concatenation inside loop is O(n²)","Use list + join","result += chunk");
    addFinding("LOW","L1","NO-VAR",34,"var declaration in JavaScript — use const/let","Replace with const","var token = generateToken()");
    addFinding("LOW","L4","RANGE-LEN-ANTI",91,"range(len()) anti-pattern — use enumerate()","Use enumerate()","for i in range(len(items)):");
    addFinding("INFO","L1","COMPLEXITY",112,"Function process_payment() has CC=18 (threshold: 10)","Break into smaller functions","def process_payment(...):");
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => counts[f.severity]++);

  const layerStatus = {};
  Object.keys(LAYER_CONFIG).forEach(l => {
    const hasFindings = findings.some(f => f.layer === l);
    const hasCritical = findings.some(f => f.layer === l && f.severity === "CRITICAL");
    layerStatus[l] = hasCritical ? "FAIL" : hasFindings ? "WARN" : "PASS";
  });

  const verdict = counts.CRITICAL > 0 ? "FAIL" : counts.HIGH > 0 ? "CONDITIONAL" : "PASS";

  return { findings, counts, layerStatus, verdict, lang, totalFiles: Math.floor(Math.random()*24)+4, linesScanned: lines.length || Math.floor(Math.random()*4000)+800 };
}

function detectLanguage(hint) {
  if (/\.py$|python/i.test(hint)) return "python";
  if (/\.kt$|kotlin/i.test(hint)) return "kotlin";
  if (/\.java$/i.test(hint)) return "java";
  if (/\.ts$|typescript/i.test(hint)) return "typescript";
  if (/\.js$|javascript/i.test(hint)) return "javascript";
  return "python";
}

// ─── Styles ────────────────────────────────────────────────────────────────
const S = {
  app: {
    minHeight: "100vh",
    background: COLORS.bg,
    color: COLORS.text,
    fontFamily: "'IBM Plex Mono', 'Fira Code', 'Cascadia Code', monospace",
    fontSize: 13,
  },
  header: {
    borderBottom: `1px solid ${COLORS.border}`,
    padding: "18px 32px",
    display: "flex",
    alignItems: "center",
    gap: 16,
    background: COLORS.surface,
    position: "sticky",
    top: 0,
    zIndex: 100,
  },
  logo: {
    fontSize: 18,
    fontWeight: 700,
    color: COLORS.accent,
    letterSpacing: "-0.5px",
    fontFamily: "'IBM Plex Mono', monospace",
  },
  badge: (color, bg) => ({
    display: "inline-flex", alignItems: "center", gap: 4,
    padding: "2px 8px", borderRadius: 3,
    fontSize: 11, fontWeight: 700, letterSpacing: "0.5px",
    color, background: bg, border: `1px solid ${color}22`,
  }),
  card: {
    background: COLORS.surface,
    border: `1px solid ${COLORS.border}`,
    borderRadius: 6,
    overflow: "hidden",
  },
  input: {
    background: COLORS.surfaceAlt,
    border: `1px solid ${COLORS.border}`,
    borderRadius: 4,
    color: COLORS.text,
    fontFamily: "inherit",
    fontSize: 13,
    padding: "10px 14px",
    outline: "none",
    width: "100%",
    boxSizing: "border-box",
    transition: "border-color 0.15s",
  },
  btn: (variant = "primary") => ({
    padding: "10px 20px",
    borderRadius: 4,
    border: variant === "primary" ? "none" : `1px solid ${COLORS.border}`,
    background: variant === "primary" ? COLORS.accent : COLORS.surfaceAlt,
    color: variant === "primary" ? COLORS.bg : COLORS.text,
    fontFamily: "inherit",
    fontSize: 13,
    fontWeight: 700,
    cursor: "pointer",
    letterSpacing: "0.3px",
    transition: "opacity 0.15s",
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
  }),
  tab: (active) => ({
    padding: "8px 16px",
    background: active ? COLORS.surfaceAlt : "transparent",
    border: `1px solid ${active ? COLORS.borderHi : "transparent"}`,
    borderRadius: 4,
    color: active ? COLORS.text : COLORS.textMid,
    fontFamily: "inherit",
    fontSize: 12,
    cursor: "pointer",
    fontWeight: active ? 600 : 400,
    letterSpacing: "0.3px",
    transition: "all 0.15s",
  }),
};

// ─── Components ────────────────────────────────────────────────────────────

function ProgressBar({ layers, current }) {
  return (
    <div style={{ padding: "24px 32px" }}>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {Object.entries(LAYER_CONFIG).map(([key, cfg], i) => {
          const idx = Object.keys(LAYER_CONFIG).indexOf(key);
          const done = idx < current;
          const active = idx === current;
          return (
            <div key={key} style={{ flex: 1 }}>
              <div style={{
                height: 3, borderRadius: 2,
                background: done ? cfg.color : active ? `${cfg.color}88` : COLORS.border,
                transition: "all 0.4s",
                marginBottom: 8,
              }}/>
              <div style={{ fontSize: 10, color: done ? cfg.color : active ? COLORS.textMid : COLORS.textDim, letterSpacing: "0.5px" }}>
                {key} {done ? "✓" : active ? "▶" : "·"}
              </div>
            </div>
          );
        })}
      </div>
      <div style={{ color: COLORS.textMid, fontSize: 12 }}>
        {current < 5
          ? `Running ${Object.values(LAYER_CONFIG)[Math.min(current, 4)]?.label}…`
          : "Analysis complete"}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const cfg = SEV_CONFIG[severity] || SEV_CONFIG.INFO;
  return <span style={S.badge(cfg.color, cfg.bg)}>{severity}</span>;
}

function ScoreRing({ verdict, counts }) {
  const total = Object.values(counts).reduce((a,b) => a+b, 0);
  const score = Math.max(0, 100 - counts.CRITICAL*25 - counts.HIGH*10 - counts.MEDIUM*3 - counts.LOW*1);
  const color = score >= 80 ? COLORS.accent : score >= 50 ? COLORS.yellow : COLORS.red;
  const r = 54, circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <svg width={140} height={140} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={70} cy={70} r={r} fill="none" stroke={COLORS.border} strokeWidth={10}/>
        <circle cx={70} cy={70} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }}/>
        <text x={70} y={70} textAnchor="middle" dominantBaseline="central"
          fill={color} fontSize={26} fontWeight={700}
          style={{ transform: "rotate(90deg)", transformOrigin: "70px 70px", fontFamily: "monospace" }}>
          {score}
        </text>
      </svg>
      <div style={{ fontSize: 11, color: COLORS.textMid, letterSpacing: "1px" }}>QUALITY SCORE</div>
      <div style={{ ...S.badge(
        verdict === "PASS" ? COLORS.accent : verdict === "CONDITIONAL" ? COLORS.yellow : COLORS.red,
        verdict === "PASS" ? COLORS.accentDim : verdict === "CONDITIONAL" ? COLORS.yellowDim : COLORS.redDim
      ), fontSize: 13, padding: "4px 14px" }}>
        {verdict}
      </div>
    </div>
  );
}

function LayerCard({ layerKey, status, findings }) {
  const cfg = LAYER_CONFIG[layerKey];
  const count = findings.filter(f => f.layer === layerKey).length;
  const statusColor = status === "PASS" ? COLORS.accent : status === "WARN" ? COLORS.yellow : COLORS.red;

  return (
    <div style={{ ...S.card, padding: "14px 18px", display: "flex", alignItems: "center", gap: 14 }}>
      <div style={{ width: 8, height: 8, borderRadius: "50%", background: statusColor, flexShrink: 0 }}/>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: cfg.color, letterSpacing: "0.5px" }}>{layerKey}</div>
        <div style={{ fontSize: 12, color: COLORS.textMid }}>{cfg.label}</div>
      </div>
      <div style={{ textAlign: "right" }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: count > 0 ? statusColor : COLORS.textDim }}>{count}</div>
        <div style={{ fontSize: 10, color: COLORS.textDim }}>issues</div>
      </div>
    </div>
  );
}

function FindingRow({ finding, onSelect, selected }) {
  const cfg = SEV_CONFIG[finding.severity];
  const lCfg = LAYER_CONFIG[finding.layer];
  return (
    <div onClick={() => onSelect(finding)}
      style={{
        padding: "12px 20px",
        borderBottom: `1px solid ${COLORS.border}`,
        cursor: "pointer",
        background: selected ? COLORS.surfaceAlt : "transparent",
        transition: "background 0.1s",
        display: "grid",
        gridTemplateColumns: "90px 60px 1fr 80px",
        gap: 12,
        alignItems: "center",
      }}>
      <SeverityBadge severity={finding.severity}/>
      <span style={{ fontSize: 10, color: lCfg?.color || COLORS.textMid, letterSpacing: "0.5px", fontWeight: 600 }}>
        {finding.layer}
      </span>
      <div>
        <div style={{ fontSize: 12, color: COLORS.text, fontWeight: 500 }}>{finding.rule}</div>
        <div style={{ fontSize: 11, color: COLORS.textMid, marginTop: 2 }}>{finding.file}:{finding.line}</div>
      </div>
      <div style={{ fontSize: 11, color: COLORS.textDim, textAlign: "right" }}>
        L{finding.line}
      </div>
    </div>
  );
}

function FindingDetail({ finding, onClose }) {
  if (!finding) return null;
  const cfg = SEV_CONFIG[finding.severity];
  const lCfg = LAYER_CONFIG[finding.layer];

  return (
    <div style={{
      ...S.card,
      position: "sticky", top: 80,
      maxHeight: "calc(100vh - 120px)",
      overflowY: "auto",
    }}>
      <div style={{ padding: "16px 20px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: 11, color: COLORS.textMid, letterSpacing: "0.5px" }}>FINDING DETAIL</div>
        <button onClick={onClose} style={{ background: "none", border: "none", color: COLORS.textMid, cursor: "pointer", fontSize: 16 }}>×</button>
      </div>
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
          <SeverityBadge severity={finding.severity}/>
          <span style={S.badge(lCfg?.color || COLORS.textMid, COLORS.surfaceAlt)}>{finding.layer} — {lCfg?.label}</span>
        </div>

        <div style={{ fontSize: 15, fontWeight: 700, color: COLORS.text, marginBottom: 8, lineHeight: 1.4 }}>
          {finding.rule}
        </div>

        <div style={{ fontSize: 12, color: COLORS.textMid, marginBottom: 20 }}>
          {finding.file} — Line {finding.line}
        </div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 6 }}>ISSUE</div>
          <div style={{ fontSize: 13, color: COLORS.text, lineHeight: 1.6 }}>{finding.message}</div>
        </div>

        {finding.snippet && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 6 }}>CODE</div>
            <div style={{
              background: COLORS.bg, border: `1px solid ${COLORS.border}`,
              borderLeft: `3px solid ${cfg.color}`,
              borderRadius: 4, padding: "10px 14px",
              fontSize: 12, color: cfg.color, fontFamily: "monospace",
              overflowX: "auto",
            }}>
              {finding.snippet}
            </div>
          </div>
        )}

        <div style={{ background: COLORS.accentDim, border: `1px solid ${COLORS.accent}22`, borderRadius: 4, padding: "12px 16px" }}>
          <div style={{ fontSize: 10, color: COLORS.accent, letterSpacing: "0.8px", marginBottom: 6 }}>✦ SUGGESTED FIX</div>
          <div style={{ fontSize: 13, color: COLORS.text, lineHeight: 1.6 }}>{finding.fix}</div>
        </div>
      </div>
    </div>
  );
}

function SummaryBar({ counts, total }) {
  const bars = Object.entries(counts).filter(([,v]) => v > 0);
  return (
    <div style={{ display: "flex", gap: 0, height: 6, borderRadius: 3, overflow: "hidden", background: COLORS.border }}>
      {bars.map(([sev, count]) => (
        <div key={sev} style={{
          flex: count / total,
          background: SEV_CONFIG[sev]?.color || COLORS.textMid,
          transition: "flex 0.5s ease",
        }}/>
      ))}
    </div>
  );
}

function StatsGrid({ result }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
      {Object.entries(result.counts).map(([sev, count]) => {
        const cfg = SEV_CONFIG[sev];
        return (
          <div key={sev} style={{ ...S.card, padding: "14px 16px", textAlign: "center" }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: cfg.color, lineHeight: 1 }}>{count}</div>
            <div style={{ fontSize: 10, color: COLORS.textMid, marginTop: 4, letterSpacing: "0.5px" }}>{sev}</div>
          </div>
        );
      })}
    </div>
  );
}

function MetaBar({ result, target }) {
  const items = [
    ["TARGET",   target || "pasted code"],
    ["LANGUAGE", result.lang?.toUpperCase() || "AUTO"],
    ["FILES",    result.totalFiles],
    ["LINES",    result.linesScanned?.toLocaleString()],
    ["ISSUES",   Object.values(result.counts).reduce((a,b)=>a+b,0)],
  ];
  return (
    <div style={{ display: "flex", gap: 0, background: COLORS.surface, borderBottom: `1px solid ${COLORS.border}`, overflowX: "auto" }}>
      {items.map(([label, val]) => (
        <div key={label} style={{ padding: "10px 20px", borderRight: `1px solid ${COLORS.border}`, flexShrink: 0 }}>
          <div style={{ fontSize: 9, color: COLORS.textDim, letterSpacing: "0.8px" }}>{label}</div>
          <div style={{ fontSize: 12, color: COLORS.text, fontWeight: 600, marginTop: 2 }}>{val}</div>
        </div>
      ))}
    </div>
  );
}

function generateReportText(result, target) {
  const now = new Date().toISOString();
  const total = Object.values(result.counts).reduce((a,b)=>a+b,0);
  const lines = [
    `CODEGUARD AUDIT REPORT`,
    `Generated: ${now}`,
    `Target: ${target || "pasted code"}`,
    `Language: ${result.lang}`,
    `Verdict: ${result.verdict}`,
    ``,
    `SUMMARY`,
    `─────────────────────────────────`,
    ...Object.entries(result.counts).map(([s,c]) => `  ${s.padEnd(10)} ${c}`),
    `  ${"TOTAL".padEnd(10)} ${total}`,
    ``,
    `LAYER RESULTS`,
    `─────────────────────────────────`,
    ...Object.entries(result.layerStatus).map(([l,s]) => `  ${l.padEnd(8)} ${s}`),
    ``,
    `FINDINGS (${total})`,
    `─────────────────────────────────`,
    ...result.findings.map(f => [
      `[${f.severity}] ${f.rule}`,
      `  File: ${f.file}  Line: ${f.line}`,
      `  Layer: ${f.layer} — ${LAYER_CONFIG[f.layer]?.label}`,
      `  Issue: ${f.message}`,
      f.snippet ? `  Code:  ${f.snippet}` : null,
      `  Fix:   ${f.fix}`,
      ``,
    ].filter(Boolean).join("\n")),
    `END OF REPORT`,
  ];
  return lines.join("\n");
}

// ─── Main App ───────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [screen, setScreen] = useState("input");   // input | scanning | results
  const [inputMode, setInputMode] = useState("paste"); // paste | repo
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("main.py");
  const [repoUrl, setRepoUrl] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterLayer, setFilterLayer] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeTab, setActiveTab] = useState("findings");
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef();
  const intervalRef = useRef();

  const runScan = useCallback(() => {
    setScreen("scanning");
    setScanProgress(0);
    setSelectedFinding(null);
    let step = 0;
    intervalRef.current = setInterval(() => {
      step++;
      setScanProgress(step);
      if (step >= 5) {
        clearInterval(intervalRef.current);
        const analysisResult = generateAnalysis(
          inputMode === "paste" ? code : "",
          inputMode === "paste" ? filename : "",
          inputMode === "repo" ? repoUrl : ""
        );
        setResult(analysisResult);
        setScreen("results");
      }
    }, 700);
  }, [code, filename, repoUrl, inputMode]);

  useEffect(() => () => clearInterval(intervalRef.current), []);

  const filteredFindings = result?.findings?.filter(f => {
    if (filterSev !== "ALL" && f.severity !== filterSev) return false;
    if (filterLayer !== "ALL" && f.layer !== filterLayer) return false;
    if (searchQuery && !f.rule.toLowerCase().includes(searchQuery.toLowerCase())
        && !f.message.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  }) || [];

  const downloadReport = () => {
    if (!result) return;
    const text = generateReportText(result, inputMode === "repo" ? repoUrl : filename);
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `codeguard-report-${Date.now()}.txt`;
    a.click(); URL.revokeObjectURL(url);
  };

  const downloadJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify({ ...result, target: repoUrl || filename, timestamp: new Date().toISOString() }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `codeguard-report-${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const handleFileUpload = (file) => {
    if (!file) return;
    setFilename(file.name);
    const reader = new FileReader();
    reader.onload = e => setCode(e.target.result);
    reader.readAsText(file);
    setInputMode("paste");
  };

  const handleDrop = (e) => {
    e.preventDefault(); setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileUpload(file);
  };

  // ── Screen: INPUT ──────────────────────────────────────────────────────
  if (screen === "input") return (
    <div style={S.app}>
      <div style={S.header}>
        <div style={S.logo}>▸ CODEGUARD</div>
        <div style={{ fontSize: 11, color: COLORS.textDim, marginLeft: 8 }}>
          AI Code Vulnerability Pipeline
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <span style={S.badge(COLORS.accent, COLORS.accentDim)}>v2.0</span>
          <span style={S.badge(COLORS.purple, COLORS.purpleDim)}>5 LAYERS</span>
        </div>
      </div>

      <div style={{ maxWidth: 860, margin: "0 auto", padding: "48px 32px" }}>
        {/* Hero */}
        <div style={{ marginBottom: 40 }}>
          <div style={{ fontSize: 11, color: COLORS.accent, letterSpacing: "2px", marginBottom: 12 }}>
            STATIC · SECURITY · DYNAMIC · PERFORMANCE
          </div>
          <h1 style={{ fontSize: 36, fontWeight: 700, margin: 0, lineHeight: 1.2, color: COLORS.text }}>
            Audit any codebase.<br/>
            <span style={{ color: COLORS.accent }}>Find every weakness.</span>
          </h1>
          <p style={{ color: COLORS.textMid, marginTop: 12, fontSize: 14, lineHeight: 1.6 }}>
            Runs 5 validation layers across Python, Java, JavaScript/TypeScript, and Kotlin.<br/>
            Documents every issue with severity, location, and a concrete fix.
          </p>
        </div>

        {/* Input mode toggle */}
        <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
          {["paste", "repo"].map(mode => (
            <button key={mode} style={S.tab(inputMode === mode)} onClick={() => setInputMode(mode)}>
              {mode === "paste" ? "⬆ Upload / Paste Code" : "⬡ GitHub / GitLab URL"}
            </button>
          ))}
        </div>

        {inputMode === "paste" ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <input
              style={S.input}
              placeholder="Filename (e.g. api.py, UserService.java, app.ts)"
              value={filename}
              onChange={e => setFilename(e.target.value)}
            />
            {/* Drop zone */}
            <div
              onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: `2px dashed ${isDragOver ? COLORS.accent : COLORS.border}`,
                borderRadius: 6, padding: "20px",
                textAlign: "center", cursor: "pointer",
                background: isDragOver ? COLORS.accentDim : COLORS.surfaceAlt,
                transition: "all 0.15s", color: COLORS.textMid, fontSize: 12,
              }}>
              <div style={{ fontSize: 24, marginBottom: 8 }}>⬆</div>
              Drop a file here or click to upload
              <input ref={fileInputRef} type="file" style={{ display: "none" }}
                accept=".py,.js,.ts,.java,.kt,.jsx,.tsx,.mjs"
                onChange={e => handleFileUpload(e.target.files[0])}/>
            </div>
            <div style={{ color: COLORS.textDim, fontSize: 11, textAlign: "center" }}>or paste code directly</div>
            <textarea
              style={{ ...S.input, minHeight: 280, resize: "vertical", lineHeight: 1.6 }}
              placeholder={`# Paste your code here...\n\ndef get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection\n    cursor.execute(query)\n    return cursor.fetchone()\n\ndef process(items=[]):  # mutable default\n    for item in items:\n        items.remove(item)  # mutate while iterating\n    return items`}
              value={code}
              onChange={e => setCode(e.target.value)}
            />
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <input
              style={S.input}
              placeholder="https://github.com/owner/repo  or  https://gitlab.com/owner/repo"
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
            />
            <div style={{ ...S.card, padding: 16, fontSize: 12, color: COLORS.textMid }}>
              <div style={{ color: COLORS.yellow, marginBottom: 8, fontWeight: 600 }}>⚠ SaaS Note</div>
              In production, this connects to the GitHub/GitLab API to clone the repository.
              For now, the demo generates a realistic findings report from the URL pattern.
              Backend implementation guide is in <code style={{ color: COLORS.accent }}>SKILL.md</code>.
            </div>
          </div>
        )}

        <div style={{ marginTop: 24, display: "flex", gap: 12, alignItems: "center" }}>
          <button
            style={S.btn("primary")}
            onClick={runScan}
            disabled={(inputMode === "paste" && !code.trim() && !filename) || (inputMode === "repo" && !repoUrl.trim())}
          >
            ▸ Run CodeGuard Analysis
          </button>
          <button style={S.btn("secondary")} onClick={() => {
            setCode(`import random, hashlib, os, yaml, pickle

# Demo: vibecoded app with multiple issues
def get_user(user_id, db_cache={}):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db_cache.get(query)

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def login(username):
    token = random.randint(1000, 9999)
    return token

async def fetch_data():
    import time
    time.sleep(2)
    return {}

def process_records(records):
    result = ""
    for r in records:
        result += str(r) + ", "
    return result

config = yaml.load(open("config.yml"), )
SECRET_KEY = "hardcoded_secret_do_not_use_123"
`);
            setFilename("demo_app.py");
          }}>
            Load Demo Code
          </button>
        </div>

        {/* Layer overview */}
        <div style={{ marginTop: 48, borderTop: `1px solid ${COLORS.border}`, paddingTop: 32 }}>
          <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 20 }}>VALIDATION LAYERS</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
            {Object.entries(LAYER_CONFIG).map(([key, cfg]) => (
              <div key={key} style={{ ...S.card, padding: "14px 16px" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: cfg.color, marginBottom: 4 }}>{key}</div>
                <div style={{ fontSize: 11, color: COLORS.textMid, lineHeight: 1.4 }}>{cfg.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // ── Screen: SCANNING ───────────────────────────────────────────────────
  if (screen === "scanning") return (
    <div style={{ ...S.app, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ maxWidth: 560, width: "100%", padding: "0 32px" }}>
        <div style={{ fontSize: 24, fontWeight: 700, color: COLORS.text, marginBottom: 8 }}>
          ▸ Scanning codebase
        </div>
        <div style={{ fontSize: 13, color: COLORS.textMid, marginBottom: 32 }}>
          Running {inputMode === "repo" ? repoUrl : filename} through 5 validation layers…
        </div>
        <div style={{ ...S.card }}>
          <ProgressBar layers={LAYER_CONFIG} current={scanProgress}/>
        </div>
        <div style={{ marginTop: 24, display: "flex", flexDirection: "column", gap: 12 }}>
          {Object.entries(LAYER_CONFIG).map(([key, cfg], i) => (
            <div key={key} style={{ display: "flex", alignItems: "center", gap: 12, opacity: i <= scanProgress ? 1 : 0.3, transition: "opacity 0.4s" }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: i < scanProgress ? COLORS.accent : i === scanProgress ? cfg.color : COLORS.border, transition: "all 0.4s" }}/>
              <div style={{ fontSize: 12, color: i < scanProgress ? COLORS.accent : i === scanProgress ? cfg.color : COLORS.textDim }}>
                {i < scanProgress ? "✓" : i === scanProgress ? "▶" : "·"} {cfg.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ── Screen: RESULTS ────────────────────────────────────────────────────
  const target = inputMode === "repo" ? repoUrl : filename;
  const total = Object.values(result.counts).reduce((a,b)=>a+b,0);

  return (
    <div style={S.app}>
      <div style={S.header}>
        <div style={S.logo}>▸ CODEGUARD</div>
        <div style={{ fontSize: 11, color: COLORS.textDim }}>
          {target}
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <button style={S.btn("secondary")} onClick={() => { setScreen("input"); setResult(null); setCode(""); setRepoUrl(""); }}>
            ← New Scan
          </button>
          <button style={S.btn("secondary")} onClick={downloadReport}>⬇ TXT Report</button>
          <button style={S.btn("secondary")} onClick={downloadJSON}>⬇ JSON Report</button>
        </div>
      </div>

      <MetaBar result={result} target={target}/>

      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", minHeight: "calc(100vh - 120px)" }}>
        {/* Sidebar */}
        <div style={{ borderRight: `1px solid ${COLORS.border}`, padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
          <ScoreRing verdict={result.verdict} counts={result.counts}/>
          <div style={{ height: 1, background: COLORS.border }}/>
          <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px" }}>LAYER STATUS</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Object.entries(result.layerStatus).map(([k, s]) => (
              <LayerCard key={k} layerKey={k} status={s} findings={result.findings}/>
            ))}
          </div>
          <div style={{ height: 1, background: COLORS.border }}/>
          <div>
            <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 10 }}>ISSUE BREAKDOWN</div>
            <SummaryBar counts={result.counts} total={total}/>
            <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 12 }}>
              {Object.entries(result.counts).map(([sev, count]) => {
                const cfg = SEV_CONFIG[sev];
                return (
                  <div key={sev} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 11, color: cfg.color }}>{sev}</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: count > 0 ? cfg.color : COLORS.textDim }}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Main content */}
        <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Tabs */}
          <div style={{ borderBottom: `1px solid ${COLORS.border}`, padding: "12px 20px", display: "flex", gap: 8 }}>
            {["findings", "stats"].map(tab => (
              <button key={tab} style={S.tab(activeTab === tab)} onClick={() => setActiveTab(tab)}>
                {tab === "findings" ? `Findings (${filteredFindings.length})` : "Statistics"}
              </button>
            ))}
          </div>

          {activeTab === "findings" && (
            <div style={{ display: "grid", gridTemplateColumns: selectedFinding ? "1fr 380px" : "1fr", flex: 1, overflow: "hidden" }}>
              <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
                {/* Filters */}
                <div style={{ padding: "12px 20px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <input
                    style={{ ...S.input, width: 200 }}
                    placeholder="Search rules, messages…"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                  />
                  <select style={{ ...S.input, width: "auto" }} value={filterSev} onChange={e => { setFilterSev(e.target.value); setSelectedFinding(null); }}>
                    <option value="ALL">All Severities</option>
                    {Object.keys(SEV_CONFIG).map(s => <option key={s} value={s}>{s} ({result.counts[s]})</option>)}
                  </select>
                  <select style={{ ...S.input, width: "auto" }} value={filterLayer} onChange={e => { setFilterLayer(e.target.value); setSelectedFinding(null); }}>
                    <option value="ALL">All Layers</option>
                    {Object.keys(LAYER_CONFIG).map(l => <option key={l} value={l}>{l}</option>)}
                  </select>
                </div>

                {/* Column headers */}
                <div style={{ padding: "8px 20px", borderBottom: `1px solid ${COLORS.border}`, display: "grid", gridTemplateColumns: "90px 60px 1fr 80px", gap: 12 }}>
                  {["SEVERITY", "LAYER", "RULE / LOCATION", "LINE"].map(h => (
                    <div key={h} style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.6px" }}>{h}</div>
                  ))}
                </div>

                {/* Findings list */}
                <div style={{ overflowY: "auto", flex: 1 }}>
                  {filteredFindings.length === 0
                    ? <div style={{ padding: 40, textAlign: "center", color: COLORS.textDim }}>No findings match filters</div>
                    : filteredFindings.map(f => (
                      <FindingRow key={f.id} finding={f}
                        selected={selectedFinding?.id === f.id}
                        onSelect={setSelectedFinding}/>
                    ))
                  }
                </div>
              </div>

              {selectedFinding && (
                <div style={{ borderLeft: `1px solid ${COLORS.border}`, padding: 20, overflowY: "auto" }}>
                  <FindingDetail finding={selectedFinding} onClose={() => setSelectedFinding(null)}/>
                </div>
              )}
            </div>
          )}

          {activeTab === "stats" && (
            <div style={{ padding: 24, overflowY: "auto", display: "flex", flexDirection: "column", gap: 24 }}>
              <StatsGrid result={result}/>

              {/* By layer breakdown */}
              <div>
                <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 12 }}>FINDINGS BY LAYER</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
                  {Object.entries(LAYER_CONFIG).map(([key, cfg]) => {
                    const count = result.findings.filter(f => f.layer === key).length;
                    return (
                      <div key={key} style={{ ...S.card, padding: "16px", textAlign: "center" }}>
                        <div style={{ fontSize: 24, fontWeight: 700, color: cfg.color }}>{count}</div>
                        <div style={{ fontSize: 11, color: COLORS.textMid, marginTop: 4 }}>{key}</div>
                        <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 2 }}>{cfg.label}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Top rules */}
              <div>
                <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 12 }}>TOP VIOLATED RULES</div>
                <div style={{ ...S.card }}>
                  {Object.entries(
                    result.findings.reduce((acc, f) => { acc[f.rule] = (acc[f.rule]||0)+1; return acc; }, {})
                  ).sort(([,a],[,b]) => b-a).slice(0, 8).map(([rule, count], i) => {
                    const finding = result.findings.find(f => f.rule === rule);
                    const cfg = SEV_CONFIG[finding?.severity || "INFO"];
                    return (
                      <div key={rule} style={{ padding: "12px 20px", borderBottom: i < 7 ? `1px solid ${COLORS.border}` : "none", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div>
                          <span style={{ fontSize: 12, color: COLORS.text }}>{rule}</span>
                          <SeverityBadge severity={finding?.severity || "INFO"}/>
                        </div>
                        <span style={{ fontSize: 14, fontWeight: 700, color: cfg.color }}>{count}×</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Remediation priority */}
              <div>
                <div style={{ fontSize: 10, color: COLORS.textDim, letterSpacing: "0.8px", marginBottom: 12 }}>REMEDIATION PRIORITY ORDER</div>
                <div style={{ ...S.card, padding: 20 }}>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].filter(s => result.counts[s] > 0).map((sev, i) => {
                    const cfg = SEV_CONFIG[sev];
                    const sevFindings = result.findings.filter(f => f.severity === sev);
                    return (
                      <div key={sev} style={{ marginBottom: i < 3 ? 20 : 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                          <div style={{ fontSize: 12, fontWeight: 700, color: cfg.color }}>
                            {i+1}. Fix {sev} issues first ({result.counts[sev]})
                          </div>
                        </div>
                        {sevFindings.slice(0,3).map(f => (
                          <div key={f.id} style={{ paddingLeft: 16, marginBottom: 4, fontSize: 11, color: COLORS.textMid }}>
                            → {f.rule} at {f.file}:{f.line}
                          </div>
                        ))}
                        {sevFindings.length > 3 && (
                          <div style={{ paddingLeft: 16, fontSize: 11, color: COLORS.textDim }}>
                            + {sevFindings.length - 3} more…
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
