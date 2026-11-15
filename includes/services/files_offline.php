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

    /** A file whose copy failed for a reason of its own is tried again after this long. */
    const RETRY_FAILED_AFTER = 86400;

    /** [key => unix time of the failure] (setting files_offline_failed). */
    private static function failedKeys(PDO $conn): array
    {
        $v = json_decode(filesSetting($conn, 'files_offline_failed'), true);
        return is_array($v) ? array_map('intval', $v) : [];
    }

    private static function saveFailedKeys(PDO $conn, array $bad): void
    {
        try {
            filesSaveSetting($conn, 'files_offline_failed', $bad ? json_encode($bad) : null);
            FilesStorageCache::$settings['files_offline_failed'] = $bad ? json_encode($bad) : null;
        } catch (Throwable $e) {
            error_log('files offline: could not save the failed list: ' . $e->getMessage());
        }
    }

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
            // A target left out ("Don't keep offline") becomes a mark: the nearest mark wins.
            $st = $conn->prepare("INSERT INTO files_offline (target_type, target_id, excluded, marked_by, marked_datetime) VALUES (?, ?, 0, ?, UTC_TIMESTAMP())
                                  ON DUPLICATE KEY UPDATE marked_by = IF(excluded = 1, VALUES(marked_by), marked_by),
                                                          marked_datetime = IF(excluded = 1, UTC_TIMESTAMP(), marked_datetime), excluded = 0");
            $st->execute([$type, $id, $analystId]);
        } catch (PDOException $e) {
            // No table yet, or not the excluded column (both come with Database Verification).
            if (filesOfflineMissingTable($e) || ($e->errorInfo[1] ?? null) === 1054) throw new InvalidArgumentException('Run System → Database Verification first.');
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
                if ($size <= self::$instantMaxBytes && !filesOfflineHasCopy($conn, $key, $size) && !self::isLocal($conn, $key)) {
                    try {
                        self::copyKey($conn, $key, $size, $row['sha256'] !== null ? (string)$row['sha256'] : null);
                    } catch (Throwable $e) {
                        error_log("files offline: could not copy {$key} now (the job will retry): " . $e->getMessage());
                    }
                }
                $ready = filesOfflineHasCopy($conn, $key, $size) || self::isLocal($conn, $key);
            }
        }
        self::forgetUsage($conn);
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
        $st = $conn->prepare("DELETE FROM files_offline WHERE target_type = ? AND target_id = ? AND excluded = 0");
        $st->execute([$type, $id]);
        if ($st->rowCount() === 0) return ['removed' => 0];
        filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => false, 'type' => $type]);
        return ['removed' => self::removeUncovered($conn, $beforeKeys)];
    }

    /**
     * "Don't keep offline": leaves a file or folder out of the folder above it that keeps
     * it offline (the nearest mark wins - a folder marked further down is kept again).
     * Only for something kept by a folder above; something marked itself is removed
     * with unmark(). Needs View. Its copies go at once (those nothing else covers).
     *
     * @return array ['removed' => copies deleted]
     */
    public static function exclude(PDO $conn, int $analystId, string $type, int $id): array
    {
        $t = self::target($conn, $analystId, $type, $id);
        $marks = filesOfflineMarks($conn);
        if ($marks === null) throw new InvalidArgumentException('Run System → Database Verification first.');
        $folders = filesOfflineCoveredFolders($conn, $marks);
        $state = $type === 'folder' ? ($folders[$id] ?? null) : filesOfflineItemCoverage($folders, $marks, $id, $t['folder_id']);
        if ($state === 'self') throw new InvalidArgumentException('This is kept offline by its own mark - choose Remove offline copy instead.');
        if ($state !== 'folder') throw new InvalidArgumentException('This is not kept offline by a folder above it.');
        $beforeKeys = filesOfflineCoveredKeys($conn, $marks);
        $conn->prepare("INSERT INTO files_offline (target_type, target_id, excluded, marked_by, marked_datetime) VALUES (?, ?, 1, ?, UTC_TIMESTAMP())
                        ON DUPLICATE KEY UPDATE excluded = 1, marked_by = VALUES(marked_by), marked_datetime = UTC_TIMESTAMP()")
             ->execute([$type, $id, $analystId]);
        filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => false, 'type' => $type, 'excluded' => true]);
        return ['removed' => self::removeUncovered($conn, $beforeKeys)];
    }

    /**
     * "Keep offline again": removes a "Don't keep offline", so the folder above keeps it
     * offline again. Needs View. The job makes the copies.
     *
     * @return array ['ok' => true]
     */
    public static function include(PDO $conn, int $analystId, string $type, int $id): array
    {
        $t = self::target($conn, $analystId, $type, $id);
        try {
            $st = $conn->prepare("DELETE FROM files_offline WHERE target_type = ? AND target_id = ? AND excluded = 1");
            $st->execute([$type, $id]);
        } catch (PDOException $e) {
            if (filesOfflineMissingTable($e) || ($e->errorInfo[1] ?? null) === 1054) throw new InvalidArgumentException('Run System → Database Verification first.');
            throw $e;
        }
        if ($st->rowCount() > 0) {
            filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => true, 'type' => $type, 'excluded' => false]);
            self::forgetUsage($conn);
        }
        return ['ok' => true];
    }

    /**
     * What is marked, for the Storage tab: ['folders' => kept, 'files' => kept, 'excluded'
     * => left out, 'people' => who marked them]. null before Database Verification.
     */
    public static function summary(PDO $conn): ?array
    {
        $marks = filesOfflineMarks($conn);
        if ($marks === null) return null;
        try {
            $people = (int)$conn->query("SELECT COUNT(DISTINCT marked_by) FROM files_offline WHERE marked_by IS NOT NULL")->fetchColumn();
        } catch (PDOException $e) {
            $people = 0;
        }
        return ['folders' => count($marks['folder']), 'files' => count($marks['item']),
                'excluded' => count($marks['exclude']['folder']) + count($marks['exclude']['item']), 'people' => $people];
    }

    /**
     * "Remove all offline copies" (Files -> Settings -> Storage, Cap::FILES_STORAGE): every
     * mark and exclusion goes, so everything is read from S3 only again. The job deletes
     * the copies (a large set would not fit in one request).
     *
     * @return array ['marks' => marks removed]
     */
    public static function clearAll(PDO $conn, int $analystId): array
    {
        try {
            $n = $conn->exec("DELETE FROM files_offline");
        } catch (PDOException $e) {
            if (filesOfflineMissingTable($e)) return ['marks' => 0];
            throw $e;
        }
        filesAudit($conn, $analystId, 'offline', ['path' => '(Settings: storage)'], ['on' => false, 'all' => true, 'marks' => (int)$n]);
        self::forgetUsage($conn);
        return ['marks' => (int)$n];
    }

    /** Deletes the copies of $beforeKeys that nothing covers any more. */
    private static function removeUncovered(PDO $conn, array $beforeKeys): int
    {
        $afterKeys = filesOfflineCoveredKeys($conn);
        $removed = 0;
        foreach (array_diff_key($beforeKeys, $afterKeys) as $key => $_) {
            if (self::removeCopy($conn, $key)) $removed++;
        }
        self::forgetUsage($conn);
        return $removed;
    }

    /**
     * True when the key is (already) stored in a folder on this server - during a move
     * from S3 back to a folder, for a file the move has verified. A copy of it would
     * only duplicate it. A lookup that fails is not "local": the copy is still made.
     */
    private static function isLocal(PDO $conn, string $key): bool
    {
        try {
            return filesStoreFor($conn, $key) instanceof LocalDriver;
        } catch (Throwable $e) {
            return false;
        }
    }

    /** Drops the job's saved usage count, which a mark or removal has just made stale. */
    private static function forgetUsage(PDO $conn): void
    {
        try {
            filesSaveSetting($conn, 'files_offline_usage', null);
            FilesStorageCache::$settings['files_offline_usage'] = null;
        } catch (Throwable $e) {
            error_log('files offline: could not reset the saved usage: ' . $e->getMessage());
        }
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
            // On Windows a rename onto a copy someone has open fails. If another request
            // put the same copy there meanwhile, that is success.
            if (!@rename($tmp, $final) && !filesOfflineHasCopy($conn, $key, $size)) {
                throw new RuntimeException('could not move the copy into place');
            }
        } finally {
            if (is_file($tmp)) @unlink($tmp);
        }
    }

    /**
     * Keeps a copy of a file being uploaded into a covered folder (or as a new version
     * of a marked file), under a temporary name. Called before the upload stores the
     * part, which may move it away; commitUploadCopy() puts it in place once the upload
     * is saved, so a failed upload leaves no copy (only a .tmp the job clears). Never
     * throws: the job fills anything missed.
     *
     * @param ?int   $itemId   the file a new version belongs to; null for a new file
     * @param string $partPath the assembled upload on this server
     * @param string $key      the storage key the upload is about to be stored under
     * @return ?string the temporary copy to pass to commitUploadCopy(); null when none was kept
     */
    public static function keepUploadCopy(PDO $conn, int $folderId, ?int $itemId, string $partPath, string $key): ?string
    {
        try {
            if (!filesOfflineApplies($conn)) return null;
            // Uploads go to the active store; a folder on this server needs no copy.
            if (filesActiveStore($conn) instanceof LocalDriver) return null;
            $marks = filesOfflineMarks($conn);
            if (!$marks || (!$marks['folder'] && !$marks['item'])) return null;
            $covered = filesOfflineItemCoverage(filesOfflineCoveredFolders($conn, $marks), $marks, $itemId ?? 0, $folderId);
            if ($covered === null) return null;
            $final = filesOfflinePath($conn, $key);
            if ($final === null) return null;
            $tmp = self::tmpFor($final);
            // The same floor as the job: copies share the disk with uploads in progress.
            $free = @disk_free_space(dirname($tmp));
            if ($free !== false && $free - (int)@filesize($partPath) < self::$minFreeBytes) {
                error_log("files offline: not enough free disk to keep a copy of the upload {$key} (the job will retry)");
                return null;
            }
            if (!@copy($partPath, $tmp)) {
                @unlink($tmp);
                error_log("files offline: could not keep a copy of the upload {$key} (the job will retry)");
                return null;
            }
            return $tmp;
        } catch (Throwable $e) {
            error_log("files offline: could not keep a copy of the upload {$key}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Puts an upload's temporary copy (from keepUploadCopy) in place, after the upload is
     * saved. Never throws.
     *
     * @param ?string $tmp  what keepUploadCopy() returned; null does nothing
     */
    public static function commitUploadCopy(PDO $conn, ?string $tmp, string $key): void
    {
        if ($tmp === null) return;
        try {
            $final = filesOfflinePath($conn, $key);
            if ($final === null || (!@rename($tmp, $final) && !is_file($final))) {
                error_log("files offline: could not keep a copy of the upload {$key} (the job will retry)");
            } else {
                // Dated now, not when the part was copied: a job run that started before
                // the upload was saved must not take it for a stale copy.
                @touch($final);
            }
            self::forgetUsage($conn);
        } catch (Throwable $e) {
            error_log("files offline: could not keep a copy of the upload {$key}: " . $e->getMessage());
        } finally {
            if (is_file($tmp)) @unlink($tmp);
        }
    }

    /**
     * The local storage folder changed (Files -> Settings -> Storage): copies under the
     * old one would never be read or tidied again, so they are removed (the job makes
     * new ones under the new folder). Nothing happens when both are the same place.
     * Only files named like our copies are touched.
     */
    public static function rootChanged(PDO $conn, string $oldRoot, string $newRoot): int
    {
        $oldRoot = rtrim(str_replace('\\', '/', $oldRoot), '/');
        $newRoot = rtrim(str_replace('\\', '/', $newRoot), '/');
        if ($oldRoot === '' || $oldRoot === $newRoot || !is_dir($oldRoot . '/offline')) return 0;
        if (str_starts_with($newRoot . '/', $oldRoot . '/offline/')) return 0;   // the new folder is inside the old copies
        try {
            // Only when PROVED to be two places; 'same' or 'unknown' keeps them (PR #318 review).
            if (storageLocationRelation(new LocalDriver($oldRoot), new LocalDriver($newRoot)) !== 'different') return 0;
        } catch (Throwable $e) {
            return 0;   // cannot tell: keep them
        }
        $removed = 0;
        foreach (self::copiesUnder($oldRoot . '/offline') as [$path, $rel]) {
            if (!filesStorageKeyIsValid($rel) && !str_ends_with($rel, '.tmp')) continue;
            if (@unlink($path)) $removed++;
        }
        self::forgetUsage($conn);
        return $removed;
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
        $r = ['copied' => 0, 'removed' => 0, 'failed' => 0, 'skipped' => 0, 'marks_dropped' => 0, 'done' => true, 'disk_full' => false];
        $started = time();
        $marks = filesOfflineMarks($conn);
        if ($marks === null) return $r;   // before Database Verification: nothing was ever marked

        $r['marks_dropped'] = $conn->exec("DELETE o FROM files_offline o LEFT JOIN files_folders f ON f.id = o.target_id
                                            WHERE o.target_type = 'folder' AND f.id IS NULL")
                            + $conn->exec("DELETE o FROM files_offline o LEFT JOIN files_items i ON i.id = o.target_id
                                            WHERE o.target_type = 'item' AND i.id IS NULL");
        if ($r['marks_dropped']) $marks = filesOfflineMarks($conn);

        $applies = filesOfflineApplies($conn);
        $covered = $applies ? self::wanted($conn, $marks) : [];

        if ($applies) {
            // Files whose copy failed for a reason of their own (missing in S3, not matching
            // its checksum) wait a day before they are tried again: one bad object must not
            // make every run fail, nor be downloaded again every few minutes.
            $bad = self::failedKeys($conn);
            $badBefore = $bad;
            foreach ($covered as $key => $c) {
                if (time() >= $deadlineUnix) { $r['done'] = false; break; }
                if (filesOfflineHasCopy($conn, $key, $c['size'])) { unset($bad[$key]); continue; }
                if (isset($bad[$key]) && $bad[$key] > time() - self::RETRY_FAILED_AFTER) { $r['skipped']++; continue; }
                try {
                    self::copyKey($conn, $key, $c['size'], $c['sha256']);
                    unset($bad[$key]);
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
                    // This file's own problem: logged once, skipped for a day.
                    error_log("files offline: could not copy {$key} (tried again in a day): " . $e->getMessage());
                    $bad[$key] = time();
                    $r['skipped']++;
                }
            }
            // Copying can take minutes: marks and uploads made meanwhile count too.
            $covered = self::wanted($conn);
            $bad = array_intersect_key($bad, $covered);   // forget what nothing covers any more
            if ($bad !== $badBefore) self::saveFailedKeys($conn, $bad);
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

        // Saved for the Storage tab, so it does not walk the folder on every load.
        $u = self::countCopies($conn);
        if ($u !== null) {
            filesSaveSetting($conn, 'files_offline_usage', json_encode($u));
            FilesStorageCache::$settings['files_offline_usage'] = json_encode($u);
        }
        return $r;
    }

    /** The covered keys that need a copy: not those already stored in a folder here. */
    private static function wanted(PDO $conn, ?array $marks = null): array
    {
        return array_filter(filesOfflineCoveredKeys($conn, $marks), fn($c, $key) => !self::isLocal($conn, (string)$key), ARRAY_FILTER_USE_BOTH);
    }

    /**
     * What the offline copies use on this server: the job's last count, or counted now
     * when there is none (never run, or a mark changed since). null when it cannot be
     * worked out.
     */
    public static function usage(PDO $conn): ?array
    {
        $saved = json_decode(filesSetting($conn, 'files_offline_usage'), true);
        if (is_array($saved) && isset($saved['files'], $saved['bytes'])) {
            return ['files' => (int)$saved['files'], 'bytes' => (int)$saved['bytes']];
        }
        return self::countCopies($conn);
    }

    /** Counts the copies on disk; null when the folder cannot be read. */
    private static function countCopies(PDO $conn): ?array
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
        return self::copiesUnder(filesOfflineRoot($conn));
    }

    /**
     * Every file under $root, as [full path, path relative to it].
     *
     * @return array<array{0: string, 1: string}>
     */
    private static function copiesUnder(string $root): array
    {
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
