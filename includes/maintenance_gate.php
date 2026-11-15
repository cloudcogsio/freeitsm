<?php
/**
 * Maintenance mode: while an in-app rollback (System -> Backups -> Restore) replaces
 * the database and the stored files, nobody else gets in. Runs on include, from
 * includes/db.php - which every database connection loads (dbConnectionOptions()),
 * including the endpoints that skip functions.php (password reset, OAuth callbacks) -
 * so every page, endpoint and job is covered without having to remember.
 *
 * - Web: 503 for everyone. API paths get JSON ({success: false, maintenance: true});
 *   pages get a plain maintenance page. The administrator running the rollback (their
 *   session AND the one-time token their browser holds) gets the progress page.
 *   api/system/backup_rollback_status.php is let through: it reports progress itself.
 * - Command line: anything under cron/ stops at once (the scheduler, every job, and
 *   any old per-job cron line), except the rollback job itself, and so do the scheduled
 *   jobs kept in scripts/ (BACKUP_MAINTENANCE_CLI_JOBS). Other scripts/ still run, for
 *   an administrator at the console.
 *
 * 🔴 It must never touch the database: the tables are being dropped and recreated.
 * One is_file() per request when maintenance mode is off. See includes/backup/maintenance.php.
 */

require_once __DIR__ . '/backup/maintenance.php';

function backupMaintenanceGate(): void
{
    if (!is_file(backupMaintenanceFile())) return;
    $root = str_replace('\\', '/', dirname(__DIR__)) . '/';
    $script = str_replace('\\', '/', (string)(realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) ?: ($_SERVER['SCRIPT_FILENAME'] ?? '')));
    $rel = strncmp($script, $root, strlen($root)) === 0 ? substr($script, strlen($root)) : ltrim((string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH), '/');

    if (PHP_SAPI === 'cli') {
        if ((str_starts_with($rel, 'cron/') && $rel !== 'cron/backup_rollback.php') || in_array($rel, BACKUP_MAINTENANCE_CLI_JOBS, true)) {
            echo "FreeITSM is in maintenance mode (a backup is being restored): nothing was started.\n";
            exit(0);
        }
        return;
    }
    if ($rel === 'api/system/backup_rollback_status.php') return;

    $st = backupMaintenanceRead() ?? ['state' => 'unknown'];
    require_once __DIR__ . '/i18n.php';   // English unless a locale is already set: no database lookup
    $t = fn(string $k, array $p = []) => I18n::t('system.backups.' . $k, $p);

    http_response_code(503);
    header('Retry-After: 120');
    header('Cache-Control: no-store');
    if (str_starts_with($rel, 'api/') || str_contains(strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? '')), 'application/json')) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'maintenance' => true, 'error' => $t('mm_api')]);
        exit;
    }
    header('Content-Type: text/html; charset=utf-8');
    backupMaintenancePage($st, backupMaintenanceIsOwner($st), $t);
    exit;
}

/** The maintenance page, or (for the administrator running it) the rollback's progress page. */
function backupMaintenancePage(array $st, bool $owner, Closure $t): void
{
    $h = fn(string $s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    $base = defined('BASE_URL') ? (string)BASE_URL : '/';
    $strings = [];
    foreach (['mm_state_starting', 'mm_state_waiting', 'mm_state_safety', 'mm_state_restoring', 'mm_state_files', 'mm_state_verifying',
              'mm_state_recovering', 'mm_state_done', 'mm_state_failed', 'mm_state_broken', 'mm_state_abandoned', 'mm_state_unknown',
              'mm_done', 'mm_failed', 'mm_broken', 'mm_stopped', 'mm_off', 'mm_off_confirm', 'mm_back', 'mm_minutes', 'mm_safety_none'] as $k) {
        $strings[$k] = $t($k);
    }
    $csrf = (string)($_SESSION['csrf_token'] ?? '');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title><?php echo $h($owner ? $t('mm_progress_title', ['set' => (string)($st['set'] ?? '')]) : $t('mm_title')); ?></title>
<style>
    :root { color-scheme: light dark; }
    body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: #f5f7fa; color: #263238; }
    .mm { max-width: 720px; margin: 8vh auto; padding: 0 20px; }
    .mm-card { background: #fff; border: 1px solid #e0e0e0; border-radius: 10px; padding: 28px; }
    h1 { font-size: 20px; margin: 0 0 10px; }
    p { font-size: 14px; line-height: 1.5; margin: 0 0 12px; }
    .mm-state { font-weight: 600; margin: 16px 0 8px; }
    .mm-log { background: #f1f3f5; border-radius: 6px; padding: 10px 12px; font: 12px/1.5 ui-monospace, Consolas, monospace; max-height: 320px; overflow: auto; white-space: pre-wrap; }
    .mm-msg { border-radius: 6px; padding: 10px 12px; font-size: 14px; margin: 12px 0; }
    .mm-msg.ok { background: #e8f5e9; color: #1b5e20; }
    .mm-msg.err { background: #ffebee; color: #b71c1c; }
    .mm-msg.warn { background: #fff8e1; color: #5d4037; }
    .mm-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    .mm-btn { padding: 8px 16px; border-radius: 5px; border: 1px solid #546e7a; background: #546e7a; color: #fff; font-size: 14px; cursor: pointer; text-decoration: none; }
    .mm-btn.plain { background: #fff; color: #263238; border-color: #ccc; }
    .mm-hidden { display: none; }
    @media (prefers-color-scheme: dark) {
        body { background: #12171b; color: #e0e6ea; }
        .mm-card { background: #1c2329; border-color: #2c363e; }
        .mm-log { background: #12171b; }
        .mm-btn.plain { background: #1c2329; color: #e0e6ea; border-color: #3a454e; }
    }
</style>
</head>
<body>
<div class="mm"><div class="mm-card">
<?php if (!$owner): ?>
    <h1><?php echo $h($t('mm_title')); ?></h1>
    <p><?php echo $h($t('mm_text')); ?></p>
<?php else: ?>
    <h1><?php echo $h($t('mm_progress_title', ['set' => (string)($st['set'] ?? '')])); ?></h1>
    <p><?php echo $h($t('mm_progress_hint')); ?></p>
    <div class="mm-state" id="mmState"></div>
    <div class="mm-msg mm-hidden" id="mmMsg"></div>
    <div class="mm-log" id="mmLog"></div>
    <div class="mm-actions">
        <button class="mm-btn plain mm-hidden" id="mmOff" type="button"><?php echo $h($t('mm_off')); ?></button>
        <a class="mm-btn mm-hidden" id="mmBack" href="<?php echo $h($base); ?>system/backups/"><?php echo $h($t('mm_back')); ?></a>
    </div>
    <script>
    (function () {
        var S = <?php echo json_encode($strings, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        var URL_ = <?php echo json_encode($base . 'api/system/backup_rollback_status.php', JSON_UNESCAPED_SLASHES); ?>;
        var CSRF = <?php echo json_encode($csrf, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        var $ = function (id) { return document.getElementById(id); };
        function fill(s, p) { return String(s).replace(/\{(\w+)\}/g, function (m, k) { return p[k] != null ? p[k] : m; }); }
        function msg(text, kind) { var m = $('mmMsg'); m.textContent = text; m.className = 'mm-msg ' + kind; }
        var timer = null;
        function show(d) {
            $('mmState').textContent = (S['mm_state_' + d.state] || S.mm_state_unknown) + (d.step ? ' - ' + d.step : '');
            $('mmLog').textContent = (d.log || []).map(function (l) { return l.at + '  ' + l.text; }).join('\n');
            $('mmLog').scrollTop = $('mmLog').scrollHeight;
            var safety = d.safety_set || S.mm_safety_none;
            if (d.state === 'done') { msg(fill(S.mm_done, { set: d.set, safety: safety }), 'ok'); $('mmBack').classList.remove('mm-hidden'); stop(); }
            else if (d.state === 'failed') { msg(fill(S.mm_failed, { error: d.error || '' }), 'err'); $('mmBack').classList.remove('mm-hidden'); stop(); }
            else if (d.state === 'abandoned') { $('mmBack').classList.remove('mm-hidden'); stop(); }
            else if (d.state === 'broken') { msg(fill(S.mm_broken, { safety: safety, error: d.error || '' }), 'err'); $('mmOff').classList.remove('mm-hidden'); }
            else if (d.stopped) { msg(fill(S.mm_stopped, { age: fill(S.mm_minutes, { n: Math.round(d.heartbeat_age / 60) }) }), 'warn'); $('mmOff').classList.remove('mm-hidden'); }
        }
        function stop() { if (timer) clearInterval(timer); timer = null; }
        function poll() {
            fetch(URL_, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) { if (d) show(d); })
                .catch(function () { /* the server may be busy: try again */ });
        }
        $('mmOff').addEventListener('click', function () {
            if (!window.confirm(S.mm_off_confirm)) return;
            fetch(URL_, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
                          body: JSON.stringify({ action: 'off' }) })
                .then(function () { window.location.href = <?php echo json_encode($base . 'system/backups/', JSON_UNESCAPED_SLASHES); ?>; });
        });
        poll();
        timer = setInterval(poll, 2000);
    })();
    </script>
<?php endif; ?>
</div></div>
</body>
</html>
<?php
}

backupMaintenanceGate();
