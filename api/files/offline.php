<?php
/**
 * POST {action: 'on'|'off'|'exclude'|'include', type: 'folder'|'item', id} - "Make
 * available offline" / "Remove offline copy" / "Don't keep offline" / "Keep offline
 * again" (includes/services/files_offline.php).
 * Changing what is kept offline needs Modify on the folder, or Cap::FILES_STORAGE.
 * POST {action: 'clear_all'} - "Remove all offline copies" (Cap::FILES_STORAGE).
 * POST {action: 'limit', gb} - the limit on what offline copies use (Cap::FILES_STORAGE).
 * POST {action: 'remove_old_folder', root} - Remove for an earlier storage folder that could
 *      not be proved to be another place: probed again first (Cap::FILES_STORAGE).
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
    if ($action === 'remove_old_folder') {
        requireCapabilityJson(Cap::FILES_STORAGE, $conn);
        try {
            filesApiOk(FilesOfflineService::removeOldRoot($conn, $analystId, (string)($in['root'] ?? '')));
        } catch (InvalidArgumentException $e) {
            filesApiFail($e->getMessage());
        }
    }
    if ($action === 'limit') {
        requireCapabilityJson(Cap::FILES_STORAGE, $conn);
        try {
            FilesOfflineService::setLimit($conn, $analystId, (int)($in['gb'] ?? -1));
        } catch (InvalidArgumentException $e) {
            filesApiFail($e->getMessage());
        }
        filesApiOk(['ok' => true]);
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
