<?php
/**
 * POST {action: 'on'|'off', type: 'folder'|'item', id} - "Make available offline" /
 * "Remove offline copy" (includes/services/files_offline.php).
 *
 * Anyone who can see the folder may do either; both are in the audit trail. Only
 * offered while Files is stored in S3-compatible storage.
 */
require_once __DIR__ . '/../../includes/files/api_bootstrap.php';
require_once __DIR__ . '/../../includes/services/files_offline.php';

// Changes data: never on a GET, which a link on another site can send (csrf.php).
csrfRequireWriteMethod();

filesApiRun(function () use ($conn, $analystId) {
    $in     = filesApiBody();
    $action = (string)($in['action'] ?? '');
    $type   = (string)($in['type'] ?? '');
    $id     = (int)($in['id'] ?? 0);
    if (!in_array($type, ['folder', 'item'], true) || $id <= 0) filesApiFail('Unknown item.');

    try {
        if ($action === 'on')  filesApiOk(FilesOfflineService::mark($conn, $analystId, $type, $id));
        if ($action === 'off') filesApiOk(FilesOfflineService::unmark($conn, $analystId, $type, $id));
    } catch (InvalidArgumentException $e) {
        // The service's own messages, written for people.
        filesApiFail($e->getMessage());
    }
    filesApiFail('Unknown action.');
});
