<?php
/**
 * Files offline copies - cron entry point.
 *
 * Makes the server copies that "Make available offline" asks for and that are not
 * there yet (files in a marked folder, restored files), removes copies nothing
 * covers any more, and forgets marks on things deleted for good. When Files is no
 * longer in S3-compatible storage at all, it removes every copy.
 * See includes/services/files_offline.php.
 *
 * Started by the built-in scheduler (cron/run.php) every five minutes, but only
 * once something has been marked. Each run works for up to eight minutes.
 *
 *   php cron/files_offline_sync.php
 *
 * Command line only.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Run from the command line.\n");
}
set_time_limit(0);

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/job_runs.php';
require_once __DIR__ . '/../includes/module_availability.php';
require_once __DIR__ . '/../includes/services/files_offline.php';

try {
    $conn = connectToDatabase();
} catch (Throwable $e) {
    fwrite(STDERR, "Database unavailable\n");
    exit(1);
}

$trigger = JobRun::scheduledTrigger();
if (cronModuleSwitchedOff($conn, 'files', 'files_offline_sync', $trigger)) exit(0);
if (!JobRun::lock($conn, 'files_offline_sync', $trigger)) exit(0);

$runId = JobRun::start($conn, 'files_offline_sync', $trigger);
try {
    $r = FilesOfflineService::sync($conn, time() + 8 * 60);
    $summary = sprintf('%d copied, %d removed, %d failed%s%s.', $r['copied'], $r['removed'], $r['failed'],
                       $r['marks_dropped'] ? ', ' . $r['marks_dropped'] . ' marks on deleted items dropped' : '',
                       $r['done'] ? '' : ' (more to do, or storage could not be reached: the next run carries on)');
    $did = $r['copied'] + $r['removed'] + $r['marks_dropped'];
    JobRun::finish($conn, $runId, $r['failed'] ? ($did > 0 ? 'partial' : 'failed') : 'ok', $r, $summary);
    echo "Files offline copies: $summary\n";
} catch (Throwable $e) {
    JobRun::fail($conn, $runId, $e);
    fwrite(STDERR, 'Files offline copies failed: ' . $e->getMessage() . "\n");
    exit(1);
} finally {
    JobRun::unlock($conn, 'files_offline_sync');
}
exit(0);
