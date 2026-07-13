/*!
 * JayShield landing page by JayHackPro
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * https://github.com/JayHackPro/JayShield
 */
(() => {
  "use strict";
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Current year in the footer.
  const yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  // Copy to clipboard on the command pills.
  for (const btn of document.querySelectorAll(".copy-cmd")) {
    btn.addEventListener("click", async () => {
      const cmd = btn.getAttribute("data-cmd") || "";
      try {
        await navigator.clipboard.writeText(cmd);
      } catch {
        const ta = document.createElement("textarea");
        ta.value = cmd;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch {}
        ta.remove();
      }
      btn.classList.add("copied");
      setTimeout(() => btn.classList.remove("copied"), 1600);
    });
  }

  // ----- Matrix rain, faint, behind the page.
  const canvas = document.querySelector(".rain");
  if (canvas && !reduced) startRain(canvas);

  function startRain(cv) {
    const ctx = cv.getContext("2d");
    const glyphs = "01</>{}[];=$#*+.ｱｶｷｹｼﾂﾃﾅﾆﾇﾊﾎﾏﾐﾑﾒﾓABCDEF0123456789".split("");
    let cols, drops, fontSize, w, h, dpr;

    function resize() {
      dpr = Math.min(devicePixelRatio || 1, 2);
      w = innerWidth; h = innerHeight;
      cv.width = Math.floor(w * dpr); cv.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      fontSize = w < 640 ? 13 : 15;
      cols = Math.ceil(w / fontSize);
      drops = new Array(cols).fill(0).map(() => Math.random() * -60);
    }
    resize();
    addEventListener("resize", resize);

    let last = 0;
    const step = 66; // about 15 fps, gentle and light on the cpu
    function frame(t) {
      requestAnimationFrame(frame);
      if (t - last < step) return;
      last = t;
      ctx.fillStyle = "rgba(5, 8, 7, 0.22)";
      ctx.fillRect(0, 0, w, h);
      ctx.font = fontSize + "px monospace";
      for (let i = 0; i < cols; i++) {
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        const ch = glyphs[(Math.random() * glyphs.length) | 0];
        // The leading glyph is brighter, the trail is dim green.
        ctx.fillStyle = Math.random() < 0.04 ? "rgba(160, 255, 200, 0.55)" : "rgba(70, 240, 138, 0.30)";
        if (y > 0) ctx.fillText(ch, x, y);
        if (y > h && Math.random() > 0.975) drops[i] = Math.random() * -20;
        drops[i] += 0.5;
      }
    }
    requestAnimationFrame(frame);
  }

  // ----- The hero terminal: type a command, then stream a scan.
  const term = document.getElementById("term");
  const replay = document.querySelector(".term-replay");
  if (term) {
    const CMD = "npx @jayhackpro/jayshield ./public_html";
    const lines = [
      { d: 350, html: "" },
      { d: 120, html: '<span class="t-head">  ▓▓ JayShield</span><span class="t-dim">  malware scanner by JayHackPro</span>' },
      { d: 120, html: "" },
      { d: 520, html: '<span class="t-dim">  Scanning 1,284 files...</span>' },
      { d: 360, html: '<span class="t-dim">  Scanned 1,284 files (24.6 MB) in 0.9s</span>' },
      { d: 140, html: "" },
      { d: 340, html: '<span class="sv-crit">  CRITICAL </span><span class="t-path">public_html/wp-content/uploads/logo.php</span>' },
      { d: 90, html: '     <span class="sv-crit">✕</span> Obfuscated eval of a decoded payload<span class="t-dim">:1</span>' },
      { d: 90, html: '       <span class="t-dim">&lt;?php @eval(base64_decode($_POST["cmd"]));</span>' },
      { d: 300, html: '<span class="sv-crit">  CRITICAL </span><span class="t-path">public_html/wp-content/uploads/thumb.png</span>' },
      { d: 90, html: '     <span class="sv-crit">✕</span> PHP code inside a media or document file' },
      { d: 300, html: '<span class="sv-high">  HIGH     </span><span class="t-path">public_html/index.html</span>' },
      { d: 90, html: '     <span class="sv-high">▲</span> Hidden or zero-size iframe<span class="t-dim">:42</span>' },
      { d: 200, html: "" },
      { d: 120, html: '<span class="t-head">  Summary</span>' },
      { d: 120, html: '  <span class="sv-crit">critical 2</span>   <span class="sv-high">high 1</span>   <span class="t-dim">medium 0   low 0</span>' },
      { d: 120, html: '<span class="t-dim">  3 files infected, 1,281 clean</span>' },
      { d: 260, html: "" },
      { d: 120, html: '<span class="t-ok">  Review the findings, then remove them safely with --quarantine</span>' }
    ];

    let timers = [];
    function clearTimers() { timers.forEach(clearTimeout); timers = []; }

    function renderFinal() {
      term.innerHTML =
        '<span class="t-line t-cmd"><span class="g">$</span> ' + escapeHtml(CMD) + "</span>" +
        lines.map((l) => '<span class="t-line">' + l.html + "</span>").join("");
    }

    function run() {
      clearTimers();
      if (reduced) { renderFinal(); return; }
      term.innerHTML = "";
      const cmdLine = document.createElement("span");
      cmdLine.className = "t-line t-cmd";
      cmdLine.innerHTML = '<span class="g">$</span> ';
      const typed = document.createElement("span");
      cmdLine.appendChild(typed);
      const caret = document.createElement("span");
      caret.className = "caret";
      cmdLine.appendChild(caret);
      term.appendChild(cmdLine);

      let i = 0;
      (function type() {
        if (i <= CMD.length) {
          typed.textContent = CMD.slice(0, i);
          i++;
          timers.push(setTimeout(type, 34));
        } else {
          caret.remove();
          stream(0);
        }
      })();
    }

    function stream(idx, caret) {
      if (idx >= lines.length) { if (caret) caret.remove(); return; }
      timers.push(setTimeout(() => {
        const el = document.createElement("span");
        el.className = "t-line";
        el.innerHTML = lines[idx].html || " ";
        term.appendChild(el);
        stream(idx + 1, caret);
      }, lines[idx].d));
    }

    // The terminal lives in the hero, always on screen, so run it on load
    // after a short beat, and let the user replay it.
    if (replay) replay.addEventListener("click", run);
    if (reduced) { renderFinal(); } else { setTimeout(run, 450); }
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
})();
