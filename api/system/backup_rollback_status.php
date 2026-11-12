<?php
/**
 * API: the progress of an in-app rollback (System -> Backups -> Restore), for the
 * administrator running it. Never touches the database: it is being replaced.
 *
 * GET  - the state, step and log while maintenance mode is on; afterwards, the outcome
 *        of the last restore
 * POST - {action: "off"}: switch maintenance mode off, only once the rollback process
 *        has stopped (gave up, or its heartbeat stopped) - never under a running one
 *
 * Only the administrator who started it: their session AND the one-time token their
 * browser was given (cookie freeitsm_rollback). Deliberately does not load
 * includes/functions.php, whose gates read the database.
 */
session_start(['read_and_close' => true]);
require_once '../../config.php';
require_once '../../includes/base_url.php';
require_once '../../includes/backup/maintenance.php';
require_once '../../includes/csrf.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$active = backupMaintenanceRead();
$st = $active ?? backupMaintenanceLast();
if ($st === null || !backupMaintenanceIsOwner($st)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Not available.']);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    echo json_encode(['success' => true, 'maintenance' => $active !== null] + backupMaintenancePublic($st));
    exit;
}

csrfRequireToken();
$in = json_decode((string)file_get_contents('php://input'), true);
if (($in['action'] ?? '') !== 'off') {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Unknown request.']);
    exit;
}
if ($active === null) {
    echo json_encode(['success' => true]);
    exit;
}
if (!backupMaintenanceStale($active)) {
    http_response_code(409);
    echo json_encode(['success' => false, 'error' => 'The restore is still working.']);
    exit;
}
backupMaintenanceEnd(['state' => 'abandoned', 'previous_state' => $active['state'] ?? null]);
error_log('[backups] maintenance mode switched off by analyst ' . (int)$active['by'] . ' after the restore stopped in state ' . ($active['state'] ?? '?'));
echo json_encode(['success' => true]);
