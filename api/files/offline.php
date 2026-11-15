<?php
/**
 * POST {action: 'on'|'off'|'exclude'|'include', type: 'folder'|'item', id} - "Make
 * available offline" / "Remove offline copy" / "Don't keep offline" / "Keep offline
 * again" (includes/services/files_offline.php). Anyone who can see the folder may.
 * POST {action: 'clear_all'} - "Remove all offline copies" (Cap::FILES_STORAGE).
 *
 * All are in the audit trail. Only offered while Files is stored in S3-compatible storage.
 */
require_once __DIR__ . '/../../includes/files/api_bootstrap.php';
require_once __DIR__ . '/../../includes/services/files_offline.php';

// Changes data: never on a GET, which a link on another site can send (csrf.php).
csrfRequireWriteMethod();

filesApiRun(function () use ($conn, $analystId) {
    $in     = filesApiBody();
    $action = (string)($in['action'] ?? '');
    if ($action === 'clear_all') {
        requireCapabilityJson(Cap::FILES_STORAGE, $conn);
        filesApiOk(FilesOfflineService::clearAll($conn, $analystId));
    }
    $type   = (string)($in['type'] ?? '');
    $id     = (int)($in['id'] ?? 0);
    if (!in_array($type, ['folder', 'item'], true) || $id <= 0) filesApiFail('Unknown item.');

    try {
        if ($action === 'on')  filesApiOk(FilesOfflineService::mark($conn, $analystId, $type, $id));
        if ($action === 'off') filesApiOk(FilesOfflineService::unmark($conn, $analystId, $type, $id));
        if ($action === 'exclude') filesApiOk(FilesOfflineService::exclude($conn, $analystId, $type, $id));
        if ($action === 'include') filesApiOk(FilesOfflineService::include($conn, $analystId, $type, $id));
    } catch (InvalidArgumentException $e) {
        // The service's own messages, written for people.
        filesApiFail($e->getMessage());
    }
    filesApiFail('Unknown action.');
});
