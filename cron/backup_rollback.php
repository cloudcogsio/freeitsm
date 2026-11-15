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
    fwrite(STDERR, "Not started from System -> Backups (maintenance mode is not waiting for this restore).\n");
    exit(2);
}
backupMaintenanceUpdate(['pid' => getmypid()], 'Restore started.');

try {
    $conn = connectToDatabase();
    $cfg = backupTargetConfig($conn);
    if ($cfg === null) throw new RuntimeException('No backup target is set.');
    $rb = new BackupRollback($conn, backupTargetDriver($cfg), $set, $passphrase, $by, dirname(__DIR__), (string)ENCRYPTION_KEY_PATH, filesActiveStore($conn));
    $r = $rb->run();
    echo 'Restore ' . $r['state'] . ($r['error'] ? ': ' . $r['error'] : '') . "\n";
    $code = $r['state'] === 'done' ? 0 : 1;
} catch (Throwable $e) {
    // Before anything was restored (no database, no target): nothing changed, so let people back in.
    backupMaintenanceUpdate([], 'Stopped: ' . $e->getMessage());
    backupMaintenanceEnd(['state' => 'failed', 'error' => $e->getMessage()]);
    fwrite(STDERR, 'Restore failed: ' . $e->getMessage() . "\n");
    $code = 1;
} finally {
    if (function_exists('sodium_memzero')) sodium_memzero($passphrase);
}
exit($code);
