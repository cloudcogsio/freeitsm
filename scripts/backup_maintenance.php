<?php
/**
 * Maintenance mode of an in-app restore (System -> Backups -> Restore), from the console.
 *
 *   php scripts/backup_maintenance.php          say whether it is on, and what the restore is doing
 *   php scripts/backup_maintenance.php --off    switch it off - only once the restore has stopped
 *
 * For when no browser can: the restoring administrator's session is gone, or the restore
 * stopped part way ("broken") and was finished by hand with scripts/backup_restore.php.
 * It never switches off under a restore whose process is still running.
 * Does not touch the database. See includes/backup/maintenance.php.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/backup/maintenance.php';

$off = in_array('--off', array_slice($argv, 1), true);
$st = backupMaintenanceRead();
if ($st === null) {
    echo "Maintenance mode is off.\n";
    $last = backupMaintenanceLast();
    if ($last) echo 'Last restore: ' . ($last['set'] ?? '?') . ' - ' . ($last['state'] ?? '?') . ' (' . ($last['ended_at'] ?? '?') . " UTC).\n";
    exit(0);
}

$age = max(0, time() - (int)($st['heartbeat'] ?? 0));
$alive = backupMaintenanceJobAlive($st);
echo 'Maintenance mode is ON: restore of backup ' . ($st['set'] ?? '?') . ', state ' . ($st['state'] ?? '?')
   . ', last activity ' . intdiv($age, 60) . " min ago.\n";
if (!empty($st['safety_set'])) echo 'Safety backup: ' . $st['safety_set'] . "\n";
if (!empty($st['error'])) echo 'Error: ' . $st['error'] . "\n";
foreach (array_slice((array)($st['log'] ?? []), -10) as $l) echo '  ' . ($l['at'] ?? '') . '  ' . ($l['text'] ?? '') . "\n";
if (!$off) exit(0);

if (!backupMaintenanceStale($st) || $alive === true) {
    echo "Not switched off: the restore is still running. Wait for it to finish.\n";
    exit(1);
}
backupMaintenanceEnd(['state' => 'abandoned', 'previous_state' => $st['state'] ?? null]);
echo "Maintenance mode switched off. Check that FreeITSM is complete before people use it.\n";
exit(0);
