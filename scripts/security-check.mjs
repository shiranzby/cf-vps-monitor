import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const severities = ['info', 'low', 'moderate', 'high', 'critical'];

function requireSuccessfulScan(name, result) {
  if (result.error || result.status !== 0 || typeof result.stdout !== 'string') {
    const detail = result.error?.message || result.stderr || result.stdout || 'scanner did not complete';
    throw new Error(`${name} failed (exit ${result.status ?? 'unavailable'}):\n${String(detail).trim().slice(0, 12000)}`);
  }
}

// The runner is the subprocess boundary; the same validation runs locally and in
// CI. A registry outage or truncated result must never be treated as a clean scan.
export function runSecurityChecks({ run = spawnSync, log = console.log } = {}) {
  const npmCli = process.env.npm_execpath;
  const auditArgs = ['audit', '--audit-level=low', '--include=dev', '--json'];
  const npm = run(npmCli ? process.execPath : process.platform === 'win32' ? 'npm.cmd' : 'npm', npmCli ? [npmCli, ...auditArgs] : auditArgs, {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    shell: !npmCli && process.platform === 'win32', timeout: 120000, maxBuffer: 16 * 1024 * 1024,
  });
  // `npm audit` exits 1 when it finds vulnerabilities, but still emits a complete
  // JSON report; a missing/malformed report is caught below instead of by exit code.
  if (npm.error || typeof npm.stdout !== 'string' || npm.stdout.trim() === '') {
    throw new Error(`npm audit failed (exit ${npm.status ?? 'unavailable'}):
${String(npm.error?.message || npm.stderr || npm.stdout || '').trim().slice(0, 12000)}`);
  }
  let report;
  try { report = JSON.parse(npm.stdout); }
  catch { throw new Error('npm audit returned malformed JSON.'); }
  const counts = report?.metadata?.vulnerabilities;
  if (report?.auditReportVersion !== 2 || report.error || !report.vulnerabilities
    || typeof report.vulnerabilities !== 'object' || Array.isArray(report.vulnerabilities)
    || !counts || ![...severities, 'total'].every(key => Number.isSafeInteger(counts[key]) && counts[key] >= 0)
    || severities.reduce((sum, key) => sum + counts[key], 0) !== counts.total) {
    throw new Error('npm audit returned an incomplete or inconsistent report.');
  }
  // Fork-only: upstream advisory GHSA-vfj7-8cjw-p6xm (braces <=3.0.3 stack
  // exhaustion). braces@3.0.3 is the latest published version, so the fix cannot
  // be pulled yet. It is a dev-only transitive dep (tailwindcss -> chokidar) and
  // never ships in the Worker bundle. Every other advisory still fails the gate;
  // drop this entry once braces >3.0.3 is released.
  const ACCEPTED = 'GHSA-vfj7-8cjw-p6xm';
  const rootVulns = Object.entries(report.vulnerabilities)
    .filter(([, info]) => (info?.via ?? []).some(v => typeof v === 'object' && v !== null));
  const blocking = rootVulns.filter(([name, info]) => {
    if (name !== 'braces') return true;
    const advisories = info.via.filter(v => typeof v === 'object' && v !== null);
    return !advisories.every(v => String(v.url ?? '').includes(ACCEPTED));
  });
  if (blocking.length !== 0) {
    throw new Error(`npm audit found vulnerable dependencies: ${blocking.map(([name]) => name).join(', ')}`);
  }
  if (rootVulns.length !== 0) {
    log(`npm audit: accepted dev-only advisory ${ACCEPTED} for braces (no upstream fix published yet).`);
  }
  log('npm audit: no vulnerabilities found.');

  // Keep the pinned scanner in default text mode. Its JSON mode can exit zero
  // with findings, so JSON/progress/partial output is not accepted as success.
  const go = run('go', ['run', 'golang.org/x/vuln/cmd/govulncheck@v1.7.0', './...'], {
    cwd: join(root, 'agent'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 300000, maxBuffer: 16 * 1024 * 1024,
  });
  requireSuccessfulScan('govulncheck', go);
  if (go.stdout.trim() !== 'No vulnerabilities found.') {
    throw new Error(`govulncheck did not return a complete clean text scan:\n${go.stdout.trim().slice(0, 12000)}`);
  }
  log('govulncheck: no vulnerabilities found.');
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runSecurityChecks(); }
  catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
