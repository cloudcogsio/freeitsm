<?php
/**
 * Files offline copies - the only write path ("Make available offline").
 *
 * What is covered, and where copies live, is in includes/files/offline.php. This
 * service adds and removes marks (api/files/offline.php), keeps a copy of uploads
 * into covered places (api/files/upload.php), and is the job files_offline_sync
 * (cron/files_offline_sync.php): fill missing copies, delete copies nothing covers,
 * forget marks on things deleted for good.
 *
 * A copy is written to a temporary name next to its final place, checked (size, and
 * SHA-256 when known) and only then renamed into place, so a half-written or wrong
 * copy is never served. Errors here never break the action that caused them: S3
 * stays the master, and the job tries again.
 */

require_once __DIR__ . '/../files/offline.php';
require_once __DIR__ . '/../files/names.php';
require_once __DIR__ . '/../files/audit.php';

/** Too little free disk to make an offline copy. */
class FilesOfflineDiskFull extends RuntimeException {}

final class FilesOfflineService
{
    /** Leftover temporary copies older than this are removed by the job. */
    const TMP_MAX_AGE = 86400;

    /**
     * Marking a single file copies it at once only up to this size; bigger files are
     * left to the job, so a click never waits for a multi-GB download from S3.
     */
    public static int $instantMaxBytes = 64 * 1024 * 1024;

    /**
     * Free disk to leave where the copies live. A copy that would leave less is not
     * made: copies share a disk with uploads in progress (_incoming), and a full disk
     * would make every upload fail.
     */
    public static int $minFreeBytes = 1024 * 1024 * 1024;

    /**
     * The target if this person can see it: ['folder_id' => int, 'item_id' => ?int,
     * 'name' => string]. Anything they cannot see is "not found", like everywhere in Files.
     */
    private static function target(PDO $conn, int $analystId, string $type, int $id): array
    {
        if ($type === 'folder') {
            if (FilesAcl::level($conn, $analystId, $id) < FilesAcl::VIEW) throw new InvalidArgumentException('Folder not found.');
            return ['folder_id' => $id, 'item_id' => null, 'name' => FilesAcl::tree($conn)[$id]['name']];
        }
        if ($type === 'item') {
            $it = filesItem($conn, $id);
            if (!$it || FilesAcl::level($conn, $analystId, (int)$it['folder_id']) < FilesAcl::VIEW) throw new InvalidArgumentException('File not found.');
            return ['folder_id' => (int)$it['folder_id'], 'item_id' => $id, 'name' => (string)$it['name']];
        }
        throw new InvalidArgumentException('Unknown item.');
    }

    /** The audit row's target for a mark. */
    private static function auditTarget(array $t): array
    {
        return $t['item_id'] === null ? ['folder_id' => $t['folder_id']]
                                       : ['folder_id' => $t['folder_id'], 'item_id' => $t['item_id'], 'item_name' => $t['name']];
    }

    /**
     * "Make available offline". Needs View. A file is copied straight away; a folder's
     * files are copied by the job.
     *
     * @param string $type  'folder' | 'item'
     * @return array ['ok' => true, 'ready' => bool (a file's copy is on the server now)]
     */
    public static function mark(PDO $conn, int $analystId, string $type, int $id): array
    {
        $t = self::target($conn, $analystId, $type, $id);
        if (!filesOfflineApplies($conn)) {
            throw new InvalidArgumentException('Offline copies are only used when files are stored in S3-compatible storage.');
        }
        try {
            $st = $conn->prepare("INSERT IGNORE INTO files_offline (target_type, target_id, marked_by, marked_datetime) VALUES (?, ?, ?, UTC_TIMESTAMP())");
            $st->execute([$type, $id, $analystId]);
        } catch (PDOException $e) {
            if (filesOfflineMissingTable($e)) throw new InvalidArgumentException('Run System → Database Verification first.');
            throw $e;
        }
        if ($st->rowCount() > 0) filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => true, 'type' => $type]);

        $ready = false;
        if ($type === 'item') {
            $v = $conn->prepare("SELECT v.storage_path, v.size_bytes, v.sha256 FROM files_items i
                                   JOIN files_versions v ON v.id = i.current_version_id WHERE i.id = ?");
            $v->execute([$id]);
            if ($row = $v->fetch(PDO::FETCH_ASSOC)) {
                $key = (string)$row['storage_path'];
                $size = (int)$row['size_bytes'];
                if ($size <= self::$instantMaxBytes && !filesOfflineHasCopy($conn, $key, $size)) {
                    try {
                        self::copyKey($conn, $key, $size, $row['sha256'] !== null ? (string)$row['sha256'] : null);
                    } catch (Throwable $e) {
                        error_log("files offline: could not copy {$key} now (the job will retry): " . $e->getMessage());
                    }
                }
                $ready = filesOfflineHasCopy($conn, $key, $size);
            }
        }
        return ['ok' => true, 'ready' => $ready];
    }

    /**
     * "Remove offline copy". Needs View; allowed whatever the storage. Deletes the
     * copies nothing else still covers (a folder above, or another marked file sharing
     * the same stored bytes).
     *
     * @return array ['removed' => copies deleted]
     */
    public static function unmark(PDO $conn, int $analystId, string $type, int $id): array
    {
        $t = self::target($conn, $analystId, $type, $id);
        $before = filesOfflineMarks($conn);
        if ($before === null) throw new InvalidArgumentException('Run System → Database Verification first.');
        $beforeKeys = filesOfflineCoveredKeys($conn, $before);
        $st = $conn->prepare("DELETE FROM files_offline WHERE target_type = ? AND target_id = ?");
        $st->execute([$type, $id]);
        if ($st->rowCount() === 0) return ['removed' => 0];
        filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => false, 'type' => $type]);

        $afterKeys = filesOfflineCoveredKeys($conn);
        $removed = 0;
        foreach (array_diff_key($beforeKeys, $afterKeys) as $key => $_) {
            if (self::removeCopy($conn, $key)) $removed++;
        }
        return ['removed' => $removed];
    }

    /**
     * Copies one stored file to its offline place: read from wherever it lives now,
     * check, rename into place.
     *
     * @throws StorageUnavailable when the store cannot be reached
     * @throws RuntimeException when the copy does not match (size or SHA-256)
     */
    public static function copyKey(PDO $conn, string $key, int $size, ?string $sha): void
    {
        $final = filesOfflinePath($conn, $key);
        if ($final === null) throw new RuntimeException('Not a stored file.');
        $tmp = self::tmpFor($final);
        $free = @disk_free_space(dirname($tmp));
        // Unknown free space (false) does not block: the write itself fails on a full disk.
        if ($free !== false && $free - $size < self::$minFreeBytes) {
            throw new FilesOfflineDiskFull('Not enough free disk for offline copies (' . (int)$free . ' bytes free).');
        }
        try {
            filesStoreFor($conn, $key)->readTo($key, $tmp);
            clearstatcache(true, $tmp);
            if (!is_file($tmp) || filesize($tmp) !== $size) throw new RuntimeException('copy did not match (size)');
            if ($sha !== null && $sha !== '' && !hash_equals(strtolower($sha), hash_file('sha256', $tmp))) {
                throw new RuntimeException('copy did not match (SHA-256)');
            }
            if (!@rename($tmp, $final)) throw new RuntimeException('could not move the copy into place');
        } finally {
            if (is_file($tmp)) @unlink($tmp);
        }
    }

    /**
     * Keeps a copy of a file being uploaded into a covered folder (or as a new version
     * of a marked file). Called before the upload stores the part, which may move it
     * away. Never throws: the job fills anything missed.
     *
     * @param ?int   $itemId   the file a new version belongs to; null for a new file
     * @param string $partPath the assembled upload on this server
     * @param string $key      the storage key the upload is about to be stored under
     */
    public static function keepUploadCopy(PDO $conn, int $folderId, ?int $itemId, string $partPath, string $key): void
    {
        try {
            if (!filesOfflineApplies($conn)) return;
            $marks = filesOfflineMarks($conn);
            if (!$marks || (!$marks['folder'] && !$marks['item'])) return;
            $covered = filesOfflineItemCoverage(filesOfflineCoveredFolders($conn, $marks), $marks, $itemId ?? 0, $folderId);
            if ($covered === null) return;
            $final = filesOfflinePath($conn, $key);
            if ($final === null) return;
            $tmp = self::tmpFor($final);
            if (!@copy($partPath, $tmp) || !@rename($tmp, $final)) {
                @unlink($tmp);
                error_log("files offline: could not keep a copy of the upload {$key} (the job will retry)");
            }
        } catch (Throwable $e) {
            error_log("files offline: could not keep a copy of the upload {$key}: " . $e->getMessage());
        }
    }

    /**
     * The job: forget marks on things deleted for good, fill missing copies, remove
     * copies nothing covers (all of them when no S3-compatible storage is in use).
     * Stops filling when storage cannot be reached; stops at $deadlineUnix.
     *
     * @return array ['copied', 'removed', 'failed', 'marks_dropped' => int, 'done' => bool,
     *               'disk_full' => bool (stopped: too little free disk)]
     */
    public static function sync(PDO $conn, int $deadlineUnix): array
    {
        $r = ['copied' => 0, 'removed' => 0, 'failed' => 0, 'marks_dropped' => 0, 'done' => true, 'disk_full' => false];
        $started = time();
        $marks = filesOfflineMarks($conn);
        if ($marks === null) return $r;   // before Database Verification: nothing was ever marked

        $r['marks_dropped'] = $conn->exec("DELETE o FROM files_offline o LEFT JOIN files_folders f ON f.id = o.target_id
                                            WHERE o.target_type = 'folder' AND f.id IS NULL")
                            + $conn->exec("DELETE o FROM files_offline o LEFT JOIN files_items i ON i.id = o.target_id
                                            WHERE o.target_type = 'item' AND i.id IS NULL");
        if ($r['marks_dropped']) $marks = filesOfflineMarks($conn);

        $applies = filesOfflineApplies($conn);
        $covered = $applies ? filesOfflineCoveredKeys($conn, $marks) : [];

        if ($applies) {
            foreach ($covered as $key => $c) {
                if (time() >= $deadlineUnix) { $r['done'] = false; break; }
                if (filesOfflineHasCopy($conn, $key, $c['size'])) continue;
                try {
                    self::copyKey($conn, $key, $c['size'], $c['sha256']);
                    $r['copied']++;
                } catch (StorageUnavailable $e) {
                    // An outage: every other copy would fail the same way. Try next run.
                    error_log('files offline: storage unavailable, copying stopped: ' . $e->getMessage());
                    $r['failed']++;
                    $r['done'] = false;
                    break;
                } catch (FilesOfflineDiskFull $e) {
                    error_log('files offline: copying stopped: ' . $e->getMessage());
                    $r['failed']++;
                    $r['done'] = false;
                    $r['disk_full'] = true;
                    break;
                } catch (Throwable $e) {
                    error_log("files offline: could not copy {$key}: " . $e->getMessage());
                    $r['failed']++;
                }
            }
            // Copying can take minutes: marks and uploads made meanwhile count too.
            $covered = filesOfflineCoveredKeys($conn);
        }

        // Remove what nothing covers, and temporary files left by a crash. A copy written
        // since this run started (a mark or an upload racing it) is left for the next run.
        foreach (self::copies($conn) as [$path, $rel]) {
            if (str_ends_with($rel, '.tmp')) {
                if (@filemtime($path) < time() - self::TMP_MAX_AGE) @unlink($path);
                continue;
            }
            if (!filesStorageKeyIsValid($rel) || isset($covered[$rel])) continue;
            clearstatcache(true, $path);
            if (@filemtime($path) > $started) continue;
            if (self::removeCopy($conn, $rel)) $r['removed']++;
        }
        return $r;
    }

    /** What the offline copies use on this server; null when it cannot be worked out. */
    public static function usage(PDO $conn): ?array
    {
        try {
            $n = 0; $bytes = 0;
            foreach (self::copies($conn) as [$path, $rel]) {
                if (!filesStorageKeyIsValid($rel)) continue;
                $n++;
                $bytes += (int)@filesize($path);
            }
            return ['files' => $n, 'bytes' => $bytes];
        } catch (Throwable $e) {
            return null;
        }
    }

    /** Deletes a key's copy (and folders left empty). True when there was one to delete. */
    private static function removeCopy(PDO $conn, string $key): bool
    {
        $p = filesOfflinePath($conn, $key);
        if ($p === null || !is_file($p)) return false;
        if (!@unlink($p)) {
            error_log("files offline: could not delete the copy {$key}");
            return false;
        }
        // yyyy/mm/dd folders left empty
        $root = filesOfflineRoot($conn);
        for ($d = dirname($p); strlen($d) > strlen($root); $d = dirname($d)) {
            if (!@rmdir($d)) break;
        }
        return true;
    }

    /**
     * Every file under the offline folder, as [full path, path relative to it].
     *
     * @return array<array{0: string, 1: string}>
     */
    private static function copies(PDO $conn): array
    {
        $root = filesOfflineRoot($conn);
        if (!is_dir($root)) return [];
        $out = [];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $path = str_replace('\\', '/', $f->getPathname());
            $out[] = [$path, substr($path, strlen($root) + 1)];
        }
        return $out;
    }

    /** A temporary name beside $final, its folders created. */
    private static function tmpFor(string $final): string
    {
        $dir = dirname($final);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new RuntimeException('The offline folder could not be created.');
        }
        return $final . '.' . bin2hex(random_bytes(6)) . '.tmp';
    }
}
