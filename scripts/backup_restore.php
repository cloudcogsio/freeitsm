<?php
/**
 * Restore FreeITSM from a backup made on System -> Backups (#286): the database, every
 * stored file and the encryption key, with nothing but the backup target and the
 * passphrase. For a fresh server, or a trial restore into a scratch database.
 *
 *   php scripts/backup_restore.php --help
 *
 * Docker: start the container with FREEITSM_SCHEDULER=0 until the restore is done, then
 *   docker compose exec app php scripts/backup_restore.php
 */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
set_time_limit(0);
// A backstop only: manifests and listings are streamed, but a very large install's maps still grow.
$memoryLimit = (string)ini_get('memory_limit');
if ($memoryLimit !== '-1' && preg_match('/^(\d+)M$/i', $memoryLimit, $mm) && (int)$mm[1] < 512) @ini_set('memory_limit', '512M');

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/backup/restore_cli.php';

exit(backupRestoreCli($argv));
