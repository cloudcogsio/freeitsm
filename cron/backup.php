<?php
/**
 * Backups (#286): takes one backup to the target set on System -> Backups.
 *
 * Scheduled by the job scheduler (job "backup", see includes/job_registry.php) at
 * the time the administrator chose; "Back up now" starts it with --manual --by=<analyst id>.
 * A first backup of a large install can take hours; it runs until it is done.
 *
 *   php cron/backup.php [--manual] [--by=<analyst id>]
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Run from the command line.\n");
}
set_time_limit(0);

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/job_runs.php';
require_once __DIR__ . '/../includes/backup/runner.php';

$opts   = getopt('', ['manual', 'by:']);
$manual = isset($opts['manual']);
$by     = isset($opts['by']) && ctype_digit((string)$opts['by']) ? (int)$opts['by'] : null;

try {
    $conn = connectToDatabase();
} catch (Throwable $e) {
    fwrite(STDERR, "Database unavailable\n");
    exit(1);
}

$trigger = $manual ? 'manual' : JobRun::scheduledTrigger();
if (!JobRun::lock($conn, 'backup', $trigger)) exit(0);

$runId = JobRun::start($conn, 'backup', $trigger, $by);
$code = 0;
try {
    $cfg = backupTargetConfig($conn);
    if ($cfg === null) throw new RuntimeException('No backup target is set (System -> Backups).');
    $runner = new BackupRunner($conn, backupTargetDriver($cfg), dirname(__DIR__));
    $r = $runner->run($manual ? 'manual' : 'scheduled', $by);
    $mb = number_format($r['size'] / 1048576, 1);
    if ($r['status'] === 'ok') {
        $summary = "Backup {$r['set']}: files {$r['files_total']}, new {$r['files_new']}, size {$mb} MB" . ($r['warning'] ? ' (with warnings)' : '') . '.';
        JobRun::finish($conn, $runId, 'ok', ['files' => $r['files_total'], 'new' => $r['files_new']], $summary);
    } else {
        $summary = 'Backup failed: ' . $r['error'];
        JobRun::finish($conn, $runId, 'failed', ['files' => $r['files_total'], 'new' => $r['files_new']], $summary);
        $code = 1;
    }
    echo $summary . "\n";
} catch (Throwable $e) {
    JobRun::fail($conn, $runId, $e);
    fwrite(STDERR, 'Backup failed: ' . $e->getMessage() . "\n");
    $code = 1;
} finally {
    JobRun::unlock($conn, 'backup');
}
exit($code);
