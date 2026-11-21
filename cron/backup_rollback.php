<?php
/**
 * Backups (#286): the in-app rollback, started by System -> Backups -> Restore
 * (BackupsService::restoreStart()), never by the scheduler. See includes/backup/rollback.php.
 *
 *   php cron/backup_rollback.php --set=<set name> --by=<analyst id>   (passphrase on standard input)
 *
 * The passphrase arrives on standard input, one line: it is never stored, never on the
 * command line and never in the environment. Maintenance mode is already on when this
 * starts (the page holds its token); the set and the analyst must match it. This is the
 * one cron/ script maintenance mode lets through.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Run from the command line.\n");
}
set_time_limit(0);
// A backstop only: manifests and listings are streamed, but a very large install's sets still grow.
$memoryLimit = (string)ini_get('memory_limit');
if ($memoryLimit !== '-1' && preg_match('/^(\d+)M$/i', $memoryLimit, $mm) && (int)$mm[1] < 512) @ini_set('memory_limit', '512M');
ignore_user_abort(true);

$line = fgets(STDIN);
$passphrase = $line === false ? '' : rtrim($line, "\r\n");

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/files/storage.php';
require_once __DIR__ . '/../includes/backup/rollback.php';

$opts = getopt('', ['set:', 'by:']);
$set  = (string)($opts['set'] ?? '');
$by   = isset($opts['by']) && ctype_digit((string)$opts['by']) ? (int)$opts['by'] : 0;

$st = backupMaintenanceRead();
if ($st === null || ($st['state'] ?? '') !== 'starting' || (string)($st['set'] ?? '') !== $set || (int)($st['by'] ?? 0) !== $by || $passphrase === '') {
    // Maintenance mode waiting for exactly this restore, which cannot run without the passphrase:
    // nothing has changed, so it is switched off now rather than left on until it counts as stopped.
    if ($st !== null && ($st['state'] ?? '') === 'starting' && (string)($st['set'] ?? '') === $set && (int)($st['by'] ?? 0) === $by && empty($st['pid'])) {
        backupMaintenanceEnd(['state' => 'failed', 'error' => backupMaintenanceT('mm_no_passphrase')]);
    }
    fwrite(STDERR, "Not started from System -> Backups (maintenance mode is not waiting for this restore).\n");
    exit(2);
}
backupMaintenanceUpdate(['pid' => getmypid()], backupMaintenanceT('mm_job_started'));

// A fatal error (out of memory, say) ends this process without run() finishing: say so at once
// rather than leave maintenance mode on until the restore counts as stopped.
register_shutdown_function('backupMaintenanceProcessEnded');

try {
    $conn = connectToDatabase();
    $cfg = backupTargetConfig($conn);
    if ($cfg === null) throw new RuntimeException(backupT('err_no_target'));
    $rb = new BackupRollback($conn, backupTargetDriver($cfg), $set, $passphrase, $by, dirname(__DIR__), (string)ENCRYPTION_KEY_PATH, filesActiveStore($conn));
    $r = $rb->run();
    echo 'Restore ' . $r['state'] . ($r['error'] ? ': ' . $r['error'] : '') . "\n";
    $code = $r['state'] === 'done' ? 0 : 1;
} catch (Throwable $e) {
    // Before anything was restored (no database, no target): nothing changed, so let people back in.
    backupMaintenanceUpdate([], backupT('rb_stopped', ['error' => $e->getMessage()]));
    backupMaintenanceEnd(['state' => 'failed', 'error' => $e->getMessage()]);
    fwrite(STDERR, 'Restore failed: ' . $e->getMessage() . "\n");
    $code = 1;
} finally {
    if (function_exists('sodium_memzero')) sodium_memzero($passphrase);
}
exit($code);
