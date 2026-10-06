/**
 * Password Security Analyzer Engine & UI Controller
 * Core analytical algorithms and interactive application script.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const passwordInput = document.getElementById('passwordInput');
  const toggleVisibilityBtn = document.getElementById('toggleVisibilityBtn');
  const generateRandomInputBtn = document.getElementById('generateRandomInputBtn');
  const copyInputBtn = document.getElementById('copyInputBtn');

  // Gauge & Summary
  const scoreGaugeMeter = document.getElementById('scoreGaugeMeter');
  const scoreNumberText = document.getElementById('scoreNumberText');
  const ratingBadge = document.getElementById('ratingBadge');
  const scoreSummary = document.getElementById('scoreSummary');

  // Metrics
  const entropyValue = document.getElementById('entropyValue');
  const charLengthValue = document.getElementById('charLengthValue');
  const charsetPoolValue = document.getElementById('charsetPoolValue');

  // Composition Bars
  const lowerFill = document.getElementById('lowerFill');
  const upperFill = document.getElementById('upperFill');
  const numberFill = document.getElementById('numberFill');
  const symbolFill = document.getElementById('symbolFill');

  const lowerCountText = document.getElementById('lowerCountText');
  const upperCountText = document.getElementById('upperCountText');
  const numberCountText = document.getElementById('numberCountText');
  const symbolCountText = document.getElementById('symbolCountText');

  // Time to crack matrix
  const timeOnlineThrottled = document.getElementById('timeOnlineThrottled');
  const timeOnlineUnthrottled = document.getElementById('timeOnlineUnthrottled');
  const timeGpuRig = document.getElementById('timeGpuRig');
  const timeQuantum = document.getElementById('timeQuantum');

  // Alert Container
  const alertList = document.getElementById('alertList');

  // HIBP Breach Element
  const hibpBadge = document.getElementById('hibpBadge');
  const hibpDetails = document.getElementById('hibpDetails');

  // Generator Elements
  const genModeRandom = document.getElementById('genModeRandom');
  const genModePassphrase = document.getElementById('genModePassphrase');
  const genOptionsRandom = document.getElementById('genOptionsRandom');
  const genOptionsPassphrase = document.getElementById('genOptionsPassphrase');

  const genLengthRange = document.getElementById('genLengthRange');
  const genLengthVal = document.getElementById('genLengthVal');
  const genIncludeUpper = document.getElementById('genIncludeUpper');
  const genIncludeLower = document.getElementById('genIncludeLower');
  const genIncludeNumbers = document.getElementById('genIncludeNumbers');
  const genIncludeSymbols = document.getElementById('genIncludeSymbols');
  const genAvoidAmbiguous = document.getElementById('genAvoidAmbiguous');

  const genWordCountRange = document.getElementById('genWordCountRange');
  const genWordCountVal = document.getElementById('genWordCountVal');
  const genSeparatorSelect = document.getElementById('genSeparatorSelect');
  const genIncludeNumberPassphrase = document.getElementById('genIncludeNumberPassphrase');
  const genCapitalizePassphrase = document.getElementById('genCapitalizePassphrase');

  const generatedPasswordDisplay = document.getElementById('generatedPasswordDisplay');
  const copyGenBtn = document.getElementById('copyGenBtn');
  const generateNewBtn = document.getElementById('generateNewBtn');
  const genScoreBadge = document.getElementById('genScoreBadge');

  // Batch Audit Elements
  const batchInput = document.getElementById('batchInput');
  const runBatchBtn = document.getElementById('runBatchBtn');
  const batchFileBtn = document.getElementById('batchFileBtn');
  const batchFileInput = document.getElementById('batchFileInput');
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  const auditTableBody = document.getElementById('auditTableBody');

  // Tabs Navigation
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  // State Variables
  let currentHibpTimer = null;
  let batchResultsCache = [];

  // Passphrase Wordlist
  const PASSPHRASE_WORDS = [
    "amber", "anchor", "arrow", "beacon", "breeze", "castle", "canyon", "cobalt",
    "cosmic", "crystal", "dagger", "dragon", "echo", "falcon", "forest", "glacier",
    "granite", "harbor", "horizon", "island", "jaguar", "legend", "matrix", "meteor",
    "monarch", "nebula", "nexus", "orbit", "panther", "phoenix", "planet", "prism",
    "pulsar", "quantum", "radial", "shadow", "signal", "silver", "solstice", "specter",
    "summit", "thunder", "timber", "titan", "torpedo", "trident", "tundra", "vector",
    "vortex", "voyage", "zenith", "zephyr"
  ];

  /* ==========================================================================
     Tab Navigation Setup
     ========================================================================== */
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });

  /* ==========================================================================
     CORE ANALYSIS ALGORITHMS
     ========================================================================== */

  /**
   * Calculates Shannon Entropy & Charset Entropy
   */
  function calculateEntropy(pwd) {
    if (!pwd) return { shannon: 0, poolSize: 0, poolEntropy: 0 };

    // Charset pool size
    let poolSize = 0;
    if (/[a-z]/.test(pwd)) poolSize += 26;
    if (/[A-Z]/.test(pwd)) poolSize += 26;
    if (/[0-9]/.test(pwd)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) poolSize += 33;

    // Charset entropy E = L * log2(N)
    const poolEntropy = pwd.length * Math.log2(poolSize || 1);

    // Shannon Entropy H = - sum(p * log2(p))
    const charCounts = {};
    for (const char of pwd) {
      charCounts[char] = (charCounts[char] || 0) + 1;
    }

    let shannon = 0;
    const len = pwd.length;
    for (const char in charCounts) {
      const p = charCounts[char] / len;
      shannon -= p * Math.log2(p);
    }
    // Total Shannon bits
    const totalShannon = shannon * len;

    return {
      shannon: Math.round(totalShannon * 10) / 10,
      poolSize,
      poolEntropy: Math.round(poolEntropy * 10) / 10
    };
  }

  /**
   * Analyzes character counts & distribution
   */
  function getCharacterComposition(pwd) {
    const len = pwd.length || 1;
    const lower = (pwd.match(/[a-z]/g) || []).length;
    const upper = (pwd.match(/[A-Z]/g) || []).length;
    const number = (pwd.match(/[0-9]/g) || []).length;
    const symbol = (pwd.match(/[^a-zA-Z0-9]/g) || []).length;

    return {
      lower: { count: lower, pct: Math.round((lower / len) * 100) },
      upper: { count: upper, pct: Math.round((upper / len) * 100) },
      number: { count: number, pct: Math.round((number / len) * 100) },
      symbol: { count: symbol, pct: Math.round((symbol / len) * 100) }
    };
  }

  /**
   * Detects weak patterns, keyboard walks, repeated characters, dates
   */
  function detectPatterns(pwd) {
    const alerts = [];
    const lowerPwd = pwd.toLowerCase();

    if (!pwd) return alerts;

    // 1. Length check
    if (pwd.length < 8) {
      alerts.push({ type: 'danger', text: 'Critically short password (< 8 characters). Vulnerable to instant brute-force.' });
    } else if (pwd.length < 12) {
      alerts.push({ type: 'warning', text: 'Password length is acceptable but under 12 characters. Recommended 14+.' });
    } else {
      alerts.push({ type: 'success', text: 'Excellent length (12+ characters).' });
    }

    // 2. Common Dictionary match
    if (typeof COMMON_PASSWORDS_SET !== 'undefined' && COMMON_PASSWORDS_SET.has(lowerPwd)) {
      alerts.push({ type: 'danger', text: 'EXACT MATCH in common leaked passwords list! Must change immediately.' });
    }

    // 3. Keyboard Walks
    if (typeof KEYBOARD_WALKS !== 'undefined') {
      for (const walk of KEYBOARD_WALKS) {
        for (let i = 0; i <= walk.length - 4; i++) {
          const sub = walk.substring(i, i + 4);
          if (lowerPwd.includes(sub) || lowerPwd.includes(sub.split('').reverse().join(''))) {
            alerts.push({ type: 'danger', text: `Contains sequential keyboard pattern ("${sub}").` });
            break;
          }
        }
      }
    }

    // 4. Repeated Chars (e.g., "aaa", "111")
    if (/(.)\1{2,}/.test(pwd)) {
      alerts.push({ type: 'warning', text: 'Contains consecutive repeated characters (e.g. "aaa" or "111").' });
    }

    // 5. Sequential Alphabetical or Numerical (e.g. "1234", "abcd")
    if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|efgh)/i.test(pwd)) {
      alerts.push({ type: 'warning', text: 'Contains simple sequential characters (e.g. "1234" or "abcd").' });
    }

    // 6. Year / Date patterns
    if (/(19\d\d|20[0-2]\d)/.test(pwd)) {
      alerts.push({ type: 'warning', text: 'Contains a 4-digit year (e.g., 1998 or 2024), reducing randomness.' });
    }

    // 7. Character set variety recommendation
    const comp = getCharacterComposition(pwd);
    const activeSets = (comp.lower.count > 0 ? 1 : 0) +
                      (comp.upper.count > 0 ? 1 : 0) +
                      (comp.number.count > 0 ? 1 : 0) +
                      (comp.symbol.count > 0 ? 1 : 0);

    if (activeSets < 3) {
      alerts.push({ type: 'warning', text: 'Lacks character set diversity. Mix uppercase, numbers, and symbols.' });
    } else {
      alerts.push({ type: 'success', text: 'Good character diversity across multiple character sets.' });
    }

    return alerts;
  }

  /**
   * Calculates time required to crack password given hash rate
   */
  function calculateCrackTimeSeconds(poolSize, length) {
    if (length === 0 || poolSize === 0) return 0;
    // Total search space combination: N^L
    // Average attempts needed: (N^L) / 2
    const totalCombinations = Math.pow(poolSize, length);
    return totalCombinations / 2;
  }

  function formatTime(seconds) {
    if (seconds <= 0) return "Instant";
    if (seconds < 0.001) return "< 1 millisecond";
    if (seconds < 1) return `${Math.round(seconds * 1000)} milliseconds`;
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    
    const years = seconds / 31536000;
    if (years < 1000) return `${Math.round(years)} years`;
    if (years < 1e6) return `${(years / 1000).toFixed(1)} thousand years`;
    if (years < 1e9) return `${(years / 1e6).toFixed(1)} million years`;
    if (years < 1e12) return `${(years / 1e9).toFixed(1)} billion years`;
    return "Trillions of years";
  }

  /**
   * Computes comprehensive overall strength score (0 to 100)
   */
  function computeOverallScore(pwd, entropy, alerts, isBreached) {
    if (!pwd) return 0;
    if (isBreached) return Math.min(15, Math.round(entropy.poolEntropy / 4));

    let score = 0;
    const len = pwd.length;

    // 1. Length contribution (up to 40 pts)
    score += Math.min(40, len * 2.8);

    // 2. Entropy contribution (up to 40 pts)
    score += Math.min(40, (entropy.poolEntropy / 128) * 40);

    // 3. Variety bonus (up to 20 pts)
    const comp = getCharacterComposition(pwd);
    let varietyCount = 0;
    if (comp.lower.count > 0) varietyCount++;
    if (comp.upper.count > 0) varietyCount++;
    if (comp.number.count > 0) varietyCount++;
    if (comp.symbol.count > 0) varietyCount++;
    score += varietyCount * 5;

    // Deductions for warnings/dangers
    for (const alert of alerts) {
      if (alert.type === 'danger') score -= 20;
      if (alert.type === 'warning') score -= 8;
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  function getRatingTier(score) {
    if (score < 25) return { label: "Very Weak", color: "var(--score-very-weak)", text: "Extremely vulnerable to dictionary & brute-force attacks." };
    if (score < 50) return { label: "Weak", color: "var(--score-weak)", text: "Low complexity. Can be cracked in a short timeframe." };
    if (score < 75) return { label: "Moderate", color: "var(--score-moderate)", text: "Decent strength, but consider adding length and symbols." };
    if (score < 90) return { label: "Strong", color: "var(--score-strong)", text: "High resistance against offline hash cracking." };
    return { label: "Extremely Fortified", color: "var(--score-fortified)", text: "Exceptional entropy and complexity. Maximum security." };
  }

  /* ==========================================================================
     PRIVACY-PRESERVING HIBP CHECK (k-Anonymity SHA-1)
     ========================================================================== */
  async function checkHIBPBreach(pwd) {
    if (!pwd || pwd.length < 3) {
      hibpBadge.className = 'hibp-badge safe';
      hibpBadge.textContent = 'Not Checked';
      hibpDetails.textContent = 'Enter a password to perform privacy-preserving breach check.';
      return false;
    }

    hibpBadge.className = 'hibp-badge loading';
    hibpBadge.textContent = 'Checking...';
    hibpDetails.textContent = 'Querying HaveIBeenPwned API using SHA-1 k-Anonymity (Prefix lookup)...';

    try {
      // 1. Convert pwd to SHA-1 Hash
      const encoder = new TextEncoder();
      const data = encoder.encode(pwd);
      const hashBuffer = await crypto.subtle.digest('SHA-1', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const sha1Hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5);

      // 2. Fetch hashes matching prefix from HIBP
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!res.ok) throw new Error('API request failed');

      const text = await res.text();
      const lines = text.split('\n');

      let breachCount = 0;
      for (const line of lines) {
        const [hashSuffix, count] = line.trim().split(':');
        if (hashSuffix === suffix) {
          breachCount = parseInt(count, 10);
          break;
        }
      }

      if (breachCount > 0) {
        hibpBadge.className = 'hibp-badge breached';
        hibpBadge.textContent = `BREACHED (${breachCount.toLocaleString()} times)`;
        hibpDetails.textContent = `CRITICAL WARNING: This password has appeared in data breaches ${breachCount.toLocaleString()} times!`;
        return true;
      } else {
        hibpBadge.className = 'hibp-badge safe';
        hibpBadge.textContent = 'SAFE (0 Breaches)';
        hibpDetails.textContent = 'No matching password hash found in known data breach databases.';
        return false;
      }
    } catch (err) {
      hibpBadge.className = 'hibp-badge safe';
      hibpBadge.textContent = 'Offline / Error';
      hibpDetails.textContent = 'Could not reach breach database API (offline mode active).';
      return false;
    }
  }

  /* ==========================================================================
     UI UPDATE CONTROLLER
     ========================================================================== */
  async function analyzeAndUpdateUI() {
    const pwd = passwordInput.value;
    const entropy = calculateEntropy(pwd);
    const comp = getCharacterComposition(pwd);
    const alerts = detectPatterns(pwd);

    // Update basic stats
    charLengthValue.textContent = pwd.length;
    entropyValue.textContent = `${entropy.poolEntropy} bits`;
    charsetPoolValue.textContent = `${entropy.poolSize} chars`;

    // Update composition bars
    lowerFill.style.width = `${comp.lower.pct}%`;
    upperFill.style.width = `${comp.upper.pct}%`;
    numberFill.style.width = `${comp.number.pct}%`;
    symbolFill.style.width = `${comp.symbol.pct}%`;

    lowerCountText.textContent = `${comp.lower.count} (${comp.lower.pct}%)`;
    upperCountText.textContent = `${comp.upper.count} (${comp.upper.pct}%)`;
    numberCountText.textContent = `${comp.number.count} (${comp.number.pct}%)`;
    symbolCountText.textContent = `${comp.symbol.count} (${comp.symbol.pct}%)`;

    // Calculate crack times
    const poolSize = entropy.poolSize;
    const len = pwd.length;
    timeOnlineThrottled.textContent = formatTime(calculateCrackTimeSeconds(poolSize, len) / 10);
    timeOnlineUnthrottled.textContent = formatTime(calculateCrackTimeSeconds(poolSize, len) / 100);
    timeGpuRig.textContent = formatTime(calculateCrackTimeSeconds(poolSize, len) / 1e11);
    timeQuantum.textContent = formatTime(calculateCrackTimeSeconds(poolSize, len) / 1e13);

    // Update Alerts List
    alertList.innerHTML = '';
    if (pwd.length === 0) {
      alertList.innerHTML = `<div class="alert-item warning">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>Enter a password above to generate real-time security alerts and pattern diagnostics.</span>
      </div>`;
    } else {
      alerts.forEach(alert => {
        const item = document.createElement('div');
        item.className = `alert-item ${alert.type}`;
        item.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          <span>${alert.text}</span>
        `;
        alertList.appendChild(item);
      });
    }

    // Debounced HIBP check
    clearTimeout(currentHibpTimer);
    let isBreached = false;
    if (pwd.length > 0) {
      currentHibpTimer = setTimeout(async () => {
        isBreached = await checkHIBPBreach(pwd);
        updateScore(pwd, entropy, alerts, isBreached);
      }, 500);
    } else {
      checkHIBPBreach('');
    }

    updateScore(pwd, entropy, alerts, isBreached);
  }

  function updateScore(pwd, entropy, alerts, isBreached) {
    const score = computeOverallScore(pwd, entropy, alerts, isBreached);
    const tier = getRatingTier(score);

    scoreNumberText.textContent = score;
    ratingBadge.textContent = tier.label;
    ratingBadge.style.color = tier.color;
    ratingBadge.style.backgroundColor = `${tier.color}22`;
    ratingBadge.style.borderColor = tier.color;
    scoreSummary.textContent = tier.text;

    // Update gauge stroke offset (dasharray 440)
    const offset = 440 - (440 * score) / 100;
    scoreGaugeMeter.style.strokeDashoffset = offset;
    scoreGaugeMeter.style.stroke = tier.color;
  }

  passwordInput.addEventListener('input', analyzeAndUpdateUI);

  // Toggle Password Mask
  toggleVisibilityBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleVisibilityBtn.innerHTML = isPassword ? 
      `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>` : 
      `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  });

  // Copy Input Password
  copyInputBtn.addEventListener('click', () => {
    if (!passwordInput.value) return;
    navigator.clipboard.writeText(passwordInput.value);
    showToast('Password copied to clipboard!');
  });

  // Generate Quick Password for Main Input
  generateRandomInputBtn.addEventListener('click', () => {
    passwordInput.value = generateRandomPassword(16, true, true, true, true, false);
    analyzeAndUpdateUI();
    showToast('Generated strong password!');
  });

  /* ==========================================================================
     PASSWORD GENERATOR SUITE
     ========================================================================== */
  function generateRandomPassword(length, upper, lower, numbers, symbols, avoidAmbiguous) {
    let chars = '';
    if (lower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) chars += '0123456789';
    if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (avoidAmbiguous) {
      chars = chars.replace(/[il1Lo0O]/g, '');
    }

    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);

    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    return result;
  }

  function generatePassphrase(wordCount, separator, addNumber, capitalize) {
    const array = new Uint32Array(wordCount);
    window.crypto.getRandomValues(array);

    let words = [];
    for (let i = 0; i < wordCount; i++) {
      let word = PASSPHRASE_WORDS[array[i] % PASSPHRASE_WORDS.length];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      words.push(word);
    }

    if (addNumber) {
      const num = Math.floor(Math.random() * 90 + 10);
      words[words.length - 1] += num;
    }

    return words.join(separator);
  }

  function updateGeneratorUI() {
    let newPassword = '';
    if (genModeRandom.checked) {
      const len = parseInt(genLengthRange.value, 10);
      newPassword = generateRandomPassword(
        len,
        genIncludeUpper.checked,
        genIncludeLower.checked,
        genIncludeNumbers.checked,
        genIncludeSymbols.checked,
        genAvoidAmbiguous.checked
      );
    } else {
      const count = parseInt(genWordCountRange.value, 10);
      newPassword = generatePassphrase(
        count,
        genSeparatorSelect.value,
        genIncludeNumberPassphrase.checked,
        genCapitalizePassphrase.checked
      );
    }

    generatedPasswordDisplay.value = newPassword;
    const entropy = calculateEntropy(newPassword);
    const alerts = detectPatterns(newPassword);
    const score = computeOverallScore(newPassword, entropy, alerts, false);
    const tier = getRatingTier(score);

    genScoreBadge.textContent = `${score}/100 - ${tier.label}`;
    genScoreBadge.style.color = tier.color;
  }

  // Generator Controls Events
  genLengthRange.addEventListener('input', (e) => {
    genLengthVal.textContent = e.target.value;
    updateGeneratorUI();
  });

  genWordCountRange.addEventListener('input', (e) => {
    genWordCountVal.textContent = e.target.value;
    updateGeneratorUI();
  });

  [genIncludeUpper, genIncludeLower, genIncludeNumbers, genIncludeSymbols, genAvoidAmbiguous,
   genSeparatorSelect, genIncludeNumberPassphrase, genCapitalizePassphrase].forEach(el => {
    el.addEventListener('change', updateGeneratorUI);
  });

  [genModeRandom, genModePassphrase].forEach(radio => {
    radio.addEventListener('change', () => {
      if (genModeRandom.checked) {
        genOptionsRandom.style.display = 'block';
        genOptionsPassphrase.style.display = 'none';
      } else {
        genOptionsRandom.style.display = 'none';
        genOptionsPassphrase.style.display = 'block';
      }
      updateGeneratorUI();
    });
  });

  generateNewBtn.addEventListener('click', updateGeneratorUI);

  copyGenBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(generatedPasswordDisplay.value);
    showToast('Generated password copied to clipboard!');
  });

  /* ==========================================================================
     BATCH SECURITY AUDIT TOOL
     ========================================================================== */
  function runBatchAudit() {
    const rawText = batchInput.value.trim();
    if (!rawText) return;

    const lines = rawText.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
    batchResultsCache = [];
    auditTableBody.innerHTML = '';

    lines.forEach((pwd, idx) => {
      const entropy = calculateEntropy(pwd);
      const alerts = detectPatterns(pwd);
      const score = computeOverallScore(pwd, entropy, alerts, false);
      const tier = getRatingTier(score);

      const resultObj = {
        id: idx + 1,
        masked: pwd.length > 4 ? pwd.substring(0, 2) + '*'.repeat(pwd.length - 4) + pwd.slice(-2) : '****',
        plain: pwd,
        length: pwd.length,
        entropyBits: entropy.poolEntropy,
        score,
        tier: tier.label,
        color: tier.color,
        vulnerabilitiesCount: alerts.filter(a => a.type === 'danger' || a.type === 'warning').length
      };

      batchResultsCache.push(resultObj);

      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="mono">${resultObj.masked}</td>
        <td>${resultObj.length}</td>
        <td>${resultObj.entropyBits} bits</td>
        <td><span style="color:${resultObj.color}; font-weight:bold;">${resultObj.score}/100</span></td>
        <td><span style="color:${resultObj.color}; font-weight:600;">${resultObj.tier}</span></td>
        <td>${resultObj.vulnerabilitiesCount} issue(s)</td>
      `;
      auditTableBody.appendChild(row);
    });

    showToast(`Batch analysis completed for ${lines.length} password(s).`);
  }

  runBatchAuditBtn?.addEventListener('click', runBatchAudit);

  // File Upload Batch
  batchFileBtn?.addEventListener('click', () => batchFileInput.click());
  batchFileInput?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      batchInput.value = event.target.result;
      runBatchAudit();
    };
    reader.readAsText(file);
  });

  // Export CSV
  exportCsvBtn?.addEventListener('click', () => {
    if (batchResultsCache.length === 0) {
      showToast('No batch audit results to export!');
      return;
    }
    let csvContent = "data:text/csv;charset=utf-8,ID,MaskedPassword,Length,EntropyBits,Score,RatingTier,VulnerabilityCount\n";
    batchResultsCache.forEach(r => {
      csvContent += `${r.id},"${r.masked}",${r.length},${r.entropyBits},${r.score},"${r.tier}",${r.vulnerabilitiesCount}\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `Password_Audit_Report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('Audit report exported to CSV!');
  });

  // Export JSON
  exportJsonBtn?.addEventListener('click', () => {
    if (batchResultsCache.length === 0) {
      showToast('No batch audit results to export!');
      return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(batchResultsCache, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", dataStr);
    link.setAttribute("download", `Password_Audit_Report_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('Audit report exported to JSON!');
  });

  /* ==========================================================================
     TOAST NOTIFIER
     ========================================================================== */
  function showToast(msg) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      <span>${msg}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 3000);
  }

  // Initialize Default State
  updateGeneratorUI();
  analyzeAndUpdateUI();
});
