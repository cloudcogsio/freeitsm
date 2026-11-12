<?php
/**
 * Maintenance mode for an in-app rollback (System -> Backups -> Restore).
 *
 * While a rollback replaces the database and the stored files, nobody may write to
 * the install. Maintenance mode is a FILE, not a setting, because the database is
 * dropped and recreated in the middle of it: a flag in system_settings would vanish
 * exactly when it matters, and the gate that checks it must not touch the database.
 *
 * The file sits beside the encryption key (outside the web root, and on the
 * encryption-keys volume under Docker, so it survives a container restart) and is
 * named after the key file, so two installs sharing a key folder do not share it:
 *   /var/www/encryption_keys/freeitsm.key  ->  freeitsm.maintenance.json
 *
 * It holds the rollback's progress (state, step, a log), who started it, a hash of
 * the one-time token their browser holds (the cookie BACKUP_MAINTENANCE_COOKIE), and a
 * heartbeat. When the rollback ends it is renamed to <name>.last-restore.json, which
 * switches maintenance mode off and keeps the outcome for System -> Backups.
 *
 * includes/maintenance_gate.php (run from includes/functions.php) acts on it;
 * api/system/backup_rollback_status.php reports it. Neither touches the database.
 */

/** The restoring administrator's browser holds this one-time token. */
const BACKUP_MAINTENANCE_COOKIE = 'freeitsm_rollback';
/** A rollback that has not written its heartbeat for this long has stopped (killed, server restarted). */
const BACKUP_MAINTENANCE_STALE = 900;
/** Log lines kept in the file. */
const BACKUP_MAINTENANCE_LOG_MAX = 200;
/**
 * Scheduled jobs that live outside cron/ (their jobRegistry() command): maintenance mode stops
 * them as it stops every cron/ script. tests/backup-rollback.php fails if a job is missing here.
 */
const BACKUP_MAINTENANCE_CLI_JOBS = ['scripts/documents_maintenance.php'];

/** States in which the rollback process is still working. */
const BACKUP_MAINTENANCE_WORKING = ['starting', 'waiting', 'safety', 'restoring', 'files', 'verifying', 'recovering'];

/**
 * The encryption key's path, resolved as includes/encryption.php does but WITHOUT
 * defining the constant: the gate can run before config.php, which may define it.
 */
function backupMaintenanceKeyPath(): string
{
    if (defined('ENCRYPTION_KEY_PATH')) return (string)ENCRYPTION_KEY_PATH;
    $p = getenv('ENCRYPTION_KEY_PATH');
    if ($p !== false && $p !== '') return $p;
    return PHP_OS_FAMILY === 'Windows' ? 'c:\\wamp64\\encryption_keys\\sdtickets.key' : '/var/www/encryption_keys/freeitsm.key';
}

/** The maintenance file of this install (it exists only while maintenance mode is on). */
function backupMaintenanceFile(): string
{
    $key = backupMaintenanceKeyPath();
    return dirname($key) . DIRECTORY_SEPARATOR . pathinfo($key, PATHINFO_FILENAME) . '.maintenance.json';
}

/** Where the outcome of the last rollback is kept once maintenance mode is off. */
function backupMaintenanceLastFile(): string
{
    $key = backupMaintenanceKeyPath();
    return dirname($key) . DIRECTORY_SEPARATOR . pathinfo($key, PATHINFO_FILENAME) . '.last-restore.json';
}

function backupMaintenanceActive(): bool
{
    return is_file(backupMaintenanceFile());
}

/**
 * The current state, or null when maintenance mode is off. A file that exists but
 * cannot be read means ON: ['state' => 'unknown'] - never "off" by mistake.
 */
function backupMaintenanceRead(): ?array
{
    $f = backupMaintenanceFile();
    if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) ? $j : ['state' => 'unknown', 'by' => null, 'heartbeat' => 0, 'log' => []];
}

/** The outcome of the last rollback, or null. */
function backupMaintenanceLast(): ?array
{
    $f = backupMaintenanceLastFile();
    if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) ? $j : null;
}

/**
 * Switches maintenance mode on for a rollback of $set started by analyst $by.
 * Returns the one-time token for the starting browser (only its hash is kept).
 *
 * @throws RuntimeException when it is already on, or the folder cannot be written
 */
function backupMaintenanceStart(int $by, string $set): string
{
    $f = backupMaintenanceFile();
    if (is_file($f)) throw new RuntimeException('Maintenance mode is already on.');
    $token = bin2hex(random_bytes(32));
    $state = [
        'state' => 'starting', 'step' => '', 'by' => $by, 'set' => $set, 'token_hash' => hash('sha256', $token),
        'started_at' => gmdate('Y-m-d H:i:s'), 'heartbeat' => time(), 'pid' => null,
        'safety_set' => null, 'result' => null, 'error' => null, 'log' => [],
    ];
    // Created exclusively: two rollbacks started at the same moment cannot both win.
    $h = @fopen($f, 'x');
    if ($h === false) {
        if (is_file($f)) throw new RuntimeException('Maintenance mode is already on.');
        throw new RuntimeException('The folder ' . dirname($f) . ' cannot be written to, so maintenance mode cannot be switched on.');
    }
    fwrite($h, json_encode($state));
    fclose($h);
    @chmod($f, 0600);
    return $token;
}

/**
 * Merges $changes into the state, refreshes the heartbeat, and appends $line to the log.
 * Written through a temporary file and a rename, so a reader never sees half a file.
 */
function backupMaintenanceUpdate(array $changes, ?string $line = null): void
{
    $st = backupMaintenanceRead();
    if ($st === null) return;   // already ended
    $st = array_merge($st, ['heartbeat' => time()], $changes);
    if ($line !== null) {
        $st['log'][] = ['at' => gmdate('Y-m-d H:i:s'), 'text' => $line];
        if (count($st['log']) > BACKUP_MAINTENANCE_LOG_MAX) $st['log'] = array_slice($st['log'], -BACKUP_MAINTENANCE_LOG_MAX);
    }
    backupMaintenanceWriteFile(backupMaintenanceFile(), $st);
}

/** Switches maintenance mode off, keeping the final state as the last restore. */
function backupMaintenanceEnd(array $changes = []): void
{
    $st = backupMaintenanceRead();
    if ($st === null) return;
    $st = array_merge($st, ['heartbeat' => time(), 'ended_at' => gmdate('Y-m-d H:i:s')], $changes);
    $last = backupMaintenanceLastFile();
    backupMaintenanceWriteFile($last, $st);
    @unlink(backupMaintenanceFile());
}

/**
 * True when the rollback process is no longer working: it gave up, or its heartbeat stopped
 * AND its process is gone. A process that is still alive is never "stopped", however long it
 * has been quiet - replaying a large database or one huge file writes no heartbeat.
 */
function backupMaintenanceStale(array $st): bool
{
    if (!in_array($st['state'] ?? '', BACKUP_MAINTENANCE_WORKING, true)) return true;
    if ((int)($st['heartbeat'] ?? 0) >= time() - BACKUP_MAINTENANCE_STALE) return false;
    return backupMaintenanceJobAlive($st) !== true;
}

/** Is the rollback's process (the pid it recorded) still running? Null when it cannot be told. */
function backupMaintenanceJobAlive(array $st): ?bool
{
    $pid = (int)($st['pid'] ?? 0);
    if ($pid <= 0) return null;
    if (PHP_OS_FAMILY === 'Windows') {
        $out = @shell_exec('tasklist /FI "PID eq ' . $pid . '" /NH 2>NUL');
        if (!is_string($out)) return null;
        return (bool)preg_match('/' . $pid . '/', $out);
    }
    if (!is_dir('/proc/self')) {
        return function_exists('posix_kill') ? @posix_kill($pid, 0) : null;
    }
    $cmd = @file_get_contents("/proc/$pid/cmdline");
    return is_string($cmd) && str_contains($cmd, 'backup_rollback');   // and not a later process that reused the pid
}

/**
 * Is this request from the administrator running the rollback: their session, and the
 * one-time token their browser was given? Reads the session without the database.
 */
function backupMaintenanceIsOwner(array $st): bool
{
    $cookie = (string)($_COOKIE[BACKUP_MAINTENANCE_COOKIE] ?? '');
    if ($cookie === '' || empty($st['token_hash']) || empty($st['by'])) return false;
    if (session_status() === PHP_SESSION_NONE && isset($_COOKIE[session_name()]) && !headers_sent()) {
        @session_start(['read_and_close' => true]);
    }
    return (int)($_SESSION['analyst_id'] ?? 0) === (int)$st['by']
        && hash_equals((string)$st['token_hash'], hash('sha256', $cookie));
}

/** What the progress page may show: no token hash, no process id. */
function backupMaintenancePublic(array $st): array
{
    $st['stopped'] = backupMaintenanceStale($st);   // before the pid is removed: it is how "stopped" is told
    unset($st['token_hash'], $st['pid']);
    $st['heartbeat_age'] = max(0, time() - (int)($st['heartbeat'] ?? 0));
    return $st;
}

function backupMaintenanceWriteFile(string $f, array $st): void
{
    $tmp = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, json_encode($st, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) === false) {
        throw new RuntimeException('The maintenance file could not be written in ' . dirname($f) . '.');
    }
    @chmod($tmp, 0600);
    if (!@rename($tmp, $f)) {
        @unlink($tmp);
        throw new RuntimeException('The maintenance file could not be written in ' . dirname($f) . '.');
    }
}
