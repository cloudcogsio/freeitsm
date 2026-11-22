<?php
/**
 * Files offline copies - the only write path ("Make available offline").
 *
 * What is covered, and where copies live, is in includes/files/offline.php. This
 * service adds and removes marks (api/files/offline.php), keeps a copy of uploads
 * into covered places (api/files/upload.php), and is the job files_offline_sync
 * (cron/files_offline_sync.php): fill missing copies, delete copies nothing covers,
 * forget marks on things deleted for good, empty an old storage folder's copies.
 *
 * Who may: changing what is kept offline - marking, removing a mark (anyone's), "Don't
 * keep offline", "Keep offline again" - needs Modify on the folder (for a file, its
 * folder), or the Files -> Storage capability. A mark covers only what the person who
 * made it can see (FilesOfflineCoverage).
 *
 * Every change to the marks runs under one named lock, with the marks read and changed
 * in one transaction; copies are deleted only after the commit. So a mark made at the
 * same moment as a removal never has its fresh copy deleted by it.
 *
 * A copy is written to a temporary name next to its final place, checked (size, and
 * SHA-256 when known) and only then renamed into place, so a half-written or wrong
 * copy is never served. files_offline_copies records each copy (or a failed attempt).
 * Errors here never break the action that caused them: S3 stays the master, and the
 * job tries again.
 */

require_once __DIR__ . '/../files/offline.php';
require_once __DIR__ . '/../files/names.php';
require_once __DIR__ . '/../files/audit.php';
require_once __DIR__ . '/../rbac.php';

/** Too little free disk to make an offline copy. */
class FilesOfflineDiskFull extends RuntimeException {}

/** The job's time ran out in the middle of a copy: what it fetched is kept, and the next run carries on. */
class FilesOfflineOutOfTime extends RuntimeException {}

final class FilesOfflineService
{
    /** Leftover temporary copies older than this are removed by the job. */
    const TMP_MAX_AGE = 86400;

    /** A file whose copy failed for a reason of its own is tried again after this long. */
    const RETRY_FAILED_AFTER = FILES_OFFLINE_RETRY_AFTER;

    /** The limits an administrator can choose for what offline copies use, in GB (0 = no limit). */
    const LIMIT_CHOICES_GB = [0, 10, 25, 50, 100, 250, 500, 1000, 2000];

    /** The message for anything asked before Database Verification has made the tables. */
    const NEEDS_VERIFICATION = 'Run System → Database Verification first.';

    /**
     * Marking a single file copies it at once only up to this size; bigger files are
     * left to the job, so a click never waits for a multi-GB download from S3. Uploads
     * are copied at once up to this size too, unless the copy can be a hard link.
     */
    public static int $instantMaxBytes = 64 * 1024 * 1024;

    /**
     * Free disk to leave where the copies live. A copy that would leave less is not
     * made: copies share a disk with uploads in progress (_incoming), and a full disk
     * would make every upload fail.
     */
    public static int $minFreeBytes = 1024 * 1024 * 1024;

    /** Seconds to wait for another change to the marks (or the job) to finish. */
    public static int $lockWait = 20;

    /** How many rows the job and a removal read at a time. */
    public static int $batch = 500;

    // ── Who, and the lock ──────────────────────────────────────────────

    /** Every change is made by someone: a missing or made-up analyst is refused. */
    private static function needAnalyst(int $analystId): void
    {
        if ($analystId < 1) throw new InvalidArgumentException('This needs a signed-in analyst.');
    }

    /**
     * The target if this person may change what is kept offline there: ['folder_id' =>
     * int, 'item_id' => ?int, 'name' => string]. Anything they cannot see is "not found",
     * like everywhere in Files; seeing it is not enough to change it - that needs Modify,
     * or the Files -> Storage capability.
     */
    private static function target(PDO $conn, int $analystId, string $type, int $id): array
    {
        if ($type === 'folder') {
            $folderId = $id;
            $level = FilesAcl::level($conn, $analystId, $id);
            if ($level < FilesAcl::VIEW) throw new InvalidArgumentException('Folder not found.');
            $t = ['folder_id' => $id, 'item_id' => null, 'name' => FilesAcl::tree($conn)[$id]['name']];
        } elseif ($type === 'item') {
            $it = filesItem($conn, $id);
            $folderId = $it ? (int)$it['folder_id'] : 0;
            $level = $it ? FilesAcl::level($conn, $analystId, $folderId) : FilesAcl::NONE;
            if ($level < FilesAcl::VIEW) throw new InvalidArgumentException('File not found.');
            $t = ['folder_id' => $folderId, 'item_id' => $id, 'name' => (string)$it['name']];
        } else {
            throw new InvalidArgumentException('Unknown item.');
        }
        if ($level < FilesAcl::MODIFY && !analystHasCapability($conn, $analystId, Cap::FILES_STORAGE)) {
            throw new InvalidArgumentException('Changing what is kept offline needs Modify permission on this folder.');
        }
        return $t;
    }

    /** The audit row's target for a mark. */
    private static function auditTarget(array $t): array
    {
        return $t['item_id'] === null ? ['folder_id' => $t['folder_id']]
                                       : ['folder_id' => $t['folder_id'], 'item_id' => $t['item_id'], 'item_name' => $t['name']];
    }

    /** The named lock every change to marks (and the job's removals) runs under. One per database. */
    private static function lockName(PDO $conn): string
    {
        return 'freeitsm_offline_' . substr(md5((string)$conn->query('SELECT DATABASE()')->fetchColumn()), 0, 16);
    }

    /** Runs $fn holding the lock. */
    private static function locked(PDO $conn, callable $fn)
    {
        $name = $conn->quote(self::lockName($conn));
        if ((int)$conn->query("SELECT GET_LOCK($name, " . (int)self::$lockWait . ")")->fetchColumn() !== 1) {
            throw new InvalidArgumentException('Offline copies are busy just now - try again in a moment.');
        }
        try {
            return $fn();
        } finally {
            $conn->query("SELECT RELEASE_LOCK($name)");
        }
    }

    /**
     * Runs $fn in a transaction (joining a caller's), turning "no such table" into the
     * Database Verification message.
     */
    private static function transaction(PDO $conn, callable $fn)
    {
        $own = !$conn->inTransaction();
        if ($own) $conn->beginTransaction();
        try {
            $out = $fn();
            if ($own) $conn->commit();
            return $out;
        } catch (Throwable $e) {
            if ($own && $conn->inTransaction()) $conn->rollBack();
            if ($e instanceof PDOException && filesOfflineMissingTable($e)) throw new InvalidArgumentException(self::NEEDS_VERIFICATION);
            throw $e;
        }
    }

    /** The mark row on a target, locked for the transaction; null when there is none. */
    private static function markRow(PDO $conn, string $type, int $id): ?array
    {
        $st = $conn->prepare("SELECT excluded, marked_by FROM files_offline WHERE target_type = ? AND target_id = ? FOR UPDATE");
        $st->execute([$type, $id]);
        return $st->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    // ── Marks ──────────────────────────────────────────────────────────

    /**
     * "Make available offline". A file up to $instantMaxBytes is copied straight away;
     * a folder's files are copied by the job. Marking something already marked by
     * someone else makes it this person's mark (their permissions decide what it covers).
     * Refused when it would take the copies past the administrator's limit.
     *
     * @param string $type  'folder' | 'item'
     * @return array ['ok' => true, 'ready' => bool (a file's copy is on the server now)]
     */
    public static function mark(PDO $conn, int $analystId, string $type, int $id): array
    {
        self::needAnalyst($analystId);
        $t = self::target($conn, $analystId, $type, $id);
        if (!filesOfflineApplies($conn)) {
            throw new InvalidArgumentException('Offline copies are only used when files are stored in S3-compatible storage.');
        }
        self::locked($conn, function () use ($conn, $analystId, $type, $id, $t) {
            self::transaction($conn, function () use ($conn, $analystId, $type, $id, $t) {
                $row = self::markRow($conn, $type, $id);
                if ($row && (int)$row['excluded'] === 0 && (int)$row['marked_by'] === $analystId) return;   // nothing changes
                // The limit is checked before anything is written.
                $limit = filesOfflineLimit($conn);
                if ($limit !== null) {
                    $used = (int)(filesOfflineUsage($conn)['bytes'] ?? 0);
                    $more = self::bytesToCopy($conn, $type, $id);
                    if ($used + $more > $limit) {
                        throw new InvalidArgumentException('Keeping this offline would take the offline copies past their limit of '
                            . self::size($limit) . ' (' . self::size($used) . ' used, about ' . self::size($more) . ' more needed). '
                            . 'An administrator can change the limit in Files -> Settings -> Storage.');
                    }
                }
                $conn->prepare("INSERT INTO files_offline (target_type, target_id, excluded, marked_by, marked_datetime) VALUES (?, ?, 0, ?, UTC_TIMESTAMP())
                                ON DUPLICATE KEY UPDATE excluded = 0, marked_by = VALUES(marked_by), marked_datetime = UTC_TIMESTAMP()")
                     ->execute([$type, $id, $analystId]);
                filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => true, 'type' => $type]);
                // A folder's files are copied by the job: their folders' ticks say so until it has run.
                if ($type === 'folder') self::rollupPending($conn, FilesAcl::descendants($conn, $id));
            });
        });

        // A file is copied straight away - outside the lock, so a download from S3 never
        // holds up other changes or the job. A removal racing it at most leaves a copy the
        // job tidies; the job never deletes a copy recorded after its run started.
        $ready = false;
        if ($type === 'item') {
            $v = $conn->prepare("SELECT v.storage_path, v.size_bytes, v.sha256 FROM files_items i
                                   JOIN files_versions v ON v.id = i.current_version_id WHERE i.id = ?");
            $v->execute([$id]);
            if ($row = $v->fetch(PDO::FETCH_ASSOC)) {
                $key = (string)$row['storage_path'];
                $size = (int)$row['size_bytes'];
                $state = filesOfflineItemStates($conn, [$id])[$id] ?? 'unknown';
                if ($state !== 'ready' && $size <= self::$instantMaxBytes && filesOfflineKept(FilesOfflineCoverage::load($conn)->item($id, $t['folder_id']))) {
                    try {
                        self::copyKey($conn, $key, $size, $row['sha256'] !== null ? (string)$row['sha256'] : null);
                        self::recordReady($conn, $key, $size);
                        $state = 'ready';
                    } catch (Throwable $e) {
                        error_log("files offline: could not copy {$key} now (the job will retry): " . $e->getMessage());
                    }
                }
                $ready = $state === 'ready';
                if (!$ready) self::rollupPending($conn, [$t['folder_id']]);
            }
        }
        return ['ok' => true, 'ready' => $ready];
    }

    /**
     * About how many bytes a mark adds that are not on the server yet: the current
     * versions in a folder (and below), or of a file, without a ready copy. Shared bytes
     * count once. An over-estimate: files left out are counted too.
     */
    private static function bytesToCopy(PDO $conn, string $type, int $id): int
    {
        $where = $type === 'folder'
            ? 'i.folder_id IN (' . implode(',', array_map('intval', FilesAcl::descendants($conn, $id))) . ')'
            : 'i.id = ' . (int)$id;
        return (int)$conn->query("SELECT COALESCE(SUM(s), 0) FROM (
                                    SELECT MAX(v.size_bytes) AS s FROM files_items i
                                      JOIN files_versions v ON v.id = i.current_version_id
                                 LEFT JOIN files_offline_copies c ON c.storage_path = v.storage_path AND c.state = 'ready'
                                     WHERE i.deleted_datetime IS NULL AND $where AND c.storage_path IS NULL
                                  GROUP BY v.storage_path) x")->fetchColumn();
    }

    /** "12.5 GB" (or MB, KB) for messages. */
    private static function size(int $bytes): string
    {
        foreach ([[1e9, 'GB'], [1e6, 'MB'], [1e3, 'KB']] as [$unit, $name]) {
            if ($bytes >= $unit) return rtrim(rtrim(number_format($bytes / $unit, 1, '.', ''), '0'), '.') . " $name";
        }
        return $bytes . ' bytes';
    }

    /**
     * "Remove offline copy": removes a mark, whoever made it. Allowed whatever the
     * storage. Deletes the copies nothing else still covers (a folder above, or another
     * kept file sharing the same stored bytes), after the commit.
     *
     * @return array ['removed' => copies deleted]
     */
    public static function unmark(PDO $conn, int $analystId, string $type, int $id): array
    {
        self::needAnalyst($analystId);
        $t = self::target($conn, $analystId, $type, $id);
        return self::locked($conn, function () use ($conn, $analystId, $type, $id, $t) {
            $changed = self::transaction($conn, function () use ($conn, $analystId, $type, $id, $t) {
                $row = self::markRow($conn, $type, $id);
                if (!$row || (int)$row['excluded'] === 1) return false;
                $conn->prepare("DELETE FROM files_offline WHERE target_type = ? AND target_id = ? AND excluded = 0")->execute([$type, $id]);
                filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => false, 'type' => $type]);
                self::dropUncoveredExclusions($conn);   // "left out" of a folder no longer kept means nothing
                return true;
            });
            return ['removed' => $changed ? self::tidyScope($conn, $type, $id) : 0];
        });
    }

    /**
     * "Don't keep offline": leaves a file or folder out of the folder above it that keeps
     * it offline (the nearest mark wins - a folder marked further down is kept again).
     * Only for something kept by a folder above; something marked itself is removed
     * with unmark(). Its copies go after the commit (those nothing else covers).
     *
     * @return array ['removed' => copies deleted]
     */
    public static function exclude(PDO $conn, int $analystId, string $type, int $id): array
    {
        self::needAnalyst($analystId);
        $t = self::target($conn, $analystId, $type, $id);
        return self::locked($conn, function () use ($conn, $analystId, $type, $id, $t) {
            self::transaction($conn, function () use ($conn, $analystId, $type, $id, $t) {
                self::markRow($conn, $type, $id);
                $cov = FilesOfflineCoverage::load($conn);
                if ($cov->marks() === null) throw new InvalidArgumentException(self::NEEDS_VERIFICATION);
                $state = $type === 'folder' ? $cov->folder($id) : $cov->item($id, $t['folder_id']);
                if ($state === 'self') throw new InvalidArgumentException('This is kept offline by its own mark - choose Remove offline copy instead.');
                if ($state !== 'folder') throw new InvalidArgumentException('This is not kept offline by a folder above it.');
                $conn->prepare("INSERT INTO files_offline (target_type, target_id, excluded, marked_by, marked_datetime) VALUES (?, ?, 1, ?, UTC_TIMESTAMP())
                                ON DUPLICATE KEY UPDATE excluded = 1, marked_by = VALUES(marked_by), marked_datetime = UTC_TIMESTAMP()")
                     ->execute([$type, $id, $analystId]);
                filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => false, 'type' => $type, 'excluded' => true]);
            });
            return ['removed' => self::tidyScope($conn, $type, $id)];
        });
    }

    /**
     * "Keep offline again": removes a "Don't keep offline", so the folder above keeps it
     * offline again. The job makes the copies.
     *
     * @return array ['ok' => true]
     */
    public static function include(PDO $conn, int $analystId, string $type, int $id): array
    {
        self::needAnalyst($analystId);
        $t = self::target($conn, $analystId, $type, $id);
        return self::locked($conn, function () use ($conn, $analystId, $type, $id, $t) {
            self::transaction($conn, function () use ($conn, $analystId, $type, $id, $t) {
                $st = $conn->prepare("DELETE FROM files_offline WHERE target_type = ? AND target_id = ? AND excluded = 1");
                $st->execute([$type, $id]);
                if ($st->rowCount() > 0) {
                    filesAudit($conn, $analystId, 'offline', self::auditTarget($t), ['on' => true, 'type' => $type, 'excluded' => false]);
                    self::rollupPending($conn, $type === 'folder' ? FilesAcl::descendants($conn, $id) : [$t['folder_id']]);
                }
            });
            return ['ok' => true];
        });
    }

    /**
     * "Remove all offline copies" (Files -> Settings -> Storage, Cap::FILES_STORAGE - the
     * caller checks it): every mark and exclusion goes, so everything is read from S3
     * only again. The job deletes the copies (a large set would not fit in one request).
     *
     * @return array ['marks' => marks removed]
     */
    public static function clearAll(PDO $conn, int $analystId): array
    {
        self::needAnalyst($analystId);
        return self::locked($conn, function () use ($conn, $analystId) {
            try {
                $n = $conn->exec("DELETE FROM files_offline");
            } catch (PDOException $e) {
                if (filesOfflineMissingTable($e)) return ['marks' => 0];
                throw $e;
            }
            filesAudit($conn, $analystId, 'offline', ['path' => '(Settings: storage)'], ['on' => false, 'all' => true, 'marks' => (int)$n]);
            return ['marks' => (int)$n];
        });
    }

    /**
     * The limit on what offline copies use (Files -> Settings -> Storage, Cap::FILES_STORAGE -
     * the caller checks it). 0 = no limit (the default).
     *
     * @param int $gb  one of LIMIT_CHOICES_GB
     */
    public static function setLimit(PDO $conn, int $analystId, int $gb): void
    {
        self::needAnalyst($analystId);
        if (!in_array($gb, self::LIMIT_CHOICES_GB, true)) throw new InvalidArgumentException('Choose the limit from the list.');
        $was = filesOfflineLimit($conn);
        filesSaveSetting($conn, 'files_offline_max_bytes', $gb > 0 ? (string)($gb * 1000 * 1000 * 1000) : null);
        filesSaveSetting($conn, 'files_offline_limit_reached', null);   // the job checks again on its next run
        FilesStorageCache::$settings = [];
        filesAudit($conn, $analystId, 'settings', ['path' => '(Settings: storage)'], [
            'offline_limit' => $gb > 0 ? $gb . ' GB' : 'none', 'was' => $was !== null ? self::size($was) : 'none',
        ]);
    }

    /**
     * What is marked, for the Storage tab: ['folders' => folder marks, 'files' => file
     * marks, 'excluded' => left out, 'people' => how many people made the folder and file
     * marks, 'inactive' => marks whose maker is no longer an active analyst (they cover
     * nothing until someone marks them again)]. null before Database Verification. A
     * database error is thrown, not reported as zero.
     */
    public static function summary(PDO $conn): ?array
    {
        $marks = filesOfflineMarks($conn);
        if ($marks === null) return null;
        $people = (int)$conn->query("SELECT COUNT(DISTINCT marked_by) FROM files_offline WHERE excluded = 0 AND marked_by IS NOT NULL")->fetchColumn();
        $inactive = (int)$conn->query("SELECT COUNT(*) FROM files_offline o LEFT JOIN analysts a ON a.id = o.marked_by
                                        WHERE o.excluded = 0 AND (a.id IS NULL OR a.is_active <> 1)")->fetchColumn();
        return ['folders' => count($marks['folder']), 'files' => count($marks['item']),
                'excluded' => count($marks['exclude']['folder']) + count($marks['exclude']['item']),
                'people' => $people, 'inactive' => $inactive];
    }

    /** What the offline copies use on this server (files_offline_copies); null before Database Verification. */
    public static function usage(PDO $conn): ?array
    {
        return filesOfflineUsage($conn);
    }

    /**
     * Drops "Don't keep offline" marks that nothing covers any more - the mark above was
     * removed, or the file or folder moved out of it - so they do not show, nor apply
     * silently if a folder above is marked again later. Things in the recycle bin keep
     * theirs (as marks do): a restore brings them back as they were.
     *
     * @return int exclusions dropped
     */
    private static function dropUncoveredExclusions(PDO $conn): int
    {
        $cov = FilesOfflineCoverage::load($conn);
        $marks = $cov->marks();
        if (!$marks || (!$marks['exclude']['folder'] && !$marks['exclude']['item'])) return 0;
        $tree = $cov->tree();
        $drop = ['folder' => [], 'item' => []];
        foreach (array_keys($marks['exclude']['folder']) as $id) {
            if (isset($tree[$id]) && $cov->folder($id) !== 'excluded') $drop['folder'][] = (int)$id;
        }
        if ($marks['exclude']['item']) {
            $ids = implode(',', array_map('intval', array_keys($marks['exclude']['item'])));
            foreach ($conn->query("SELECT id, folder_id FROM files_items WHERE deleted_datetime IS NULL AND id IN ($ids)")->fetchAll(PDO::FETCH_NUM) as [$id, $fid]) {
                if (!isset($tree[(int)$fid])) continue;   // its folder is in the recycle bin
                if ($cov->item((int)$id, (int)$fid) !== 'excluded') $drop['item'][] = (int)$id;
            }
        }
        $n = 0;
        foreach ($drop as $type => $ids) {
            if (!$ids) continue;
            $n += $conn->exec("DELETE FROM files_offline WHERE excluded = 1 AND target_type = " . $conn->quote($type) . " AND target_id IN (" . implode(',', $ids) . ")");
        }
        return $n;
    }

    // ── Folder ticks (files_offline_folders) ───────────────────────────

    /**
     * Marks folders' ticks pending: something in them now waits for a copy. The job works
     * out the real state at the end of its next run.
     *
     * @param int[] $folderIds
     */
    private static function rollupPending(PDO $conn, array $folderIds): void
    {
        $folderIds = array_values(array_unique(array_map('intval', $folderIds)));
        try {
            foreach (array_chunk($folderIds, 500) as $chunk) {
                $conn->exec("INSERT INTO files_offline_folders (folder_id, state, updated_datetime) VALUES "
                            . implode(',', array_map(fn($f) => "($f, 2, UTC_TIMESTAMP(3))", $chunk))
                            . " ON DUPLICATE KEY UPDATE state = 2, updated_datetime = UTC_TIMESTAMP(3)");
            }
        } catch (PDOException $e) {
            if (!filesOfflineMissingTable($e)) throw $e;
        }
    }

    /**
     * Something may have been added to these folders without a copy - restored from the
     * recycle bin, moved or copied in, a version restored, an upload copy that did not
     * land: a tick recorded as ready says "being made available" until the job has looked
     * again. Only existing rows change (a kept folder without a row is pending anyway), so
     * this does nothing on an install that does not use offline copies. Never throws.
     *
     * @param int[] $folderIds
     */
    public static function foldersChanged(PDO $conn, array $folderIds): void
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $folderIds))));
        try {
            foreach (array_chunk($ids, 500) as $chunk) {
                $conn->exec("UPDATE files_offline_folders SET state = 2, updated_datetime = UTC_TIMESTAMP(3)
                              WHERE state <> 2 AND folder_id IN (" . implode(',', $chunk) . ")");
            }
        } catch (Throwable $e) {
            if (!($e instanceof PDOException && filesOfflineMissingTable($e))) error_log('files offline: could not update the folder ticks: ' . $e->getMessage());
        }
    }

    /**
     * Rewrites files_offline_folders from the copy records (filesOfflineFolderRollup): one
     * grouped query, at the end of each run. A folder marked pending after the work-out
     * started keeps its pending row - it is worked out again on the next run.
     */
    private static function rollup(PDO $conn): void
    {
        $since = (string)$conn->query("SELECT UTC_TIMESTAMP(3)")->fetchColumn();
        $rows = filesOfflineFolderRollup($conn, FilesOfflineCoverage::load($conn));
        if ($rows === null) return;   // cannot be worked out now: the old rows stay
        self::transaction($conn, function () use ($conn, $rows, $since) {
            $conn->prepare("DELETE FROM files_offline_folders WHERE updated_datetime < ?")->execute([$since]);
            foreach (array_chunk($rows, 500, true) as $chunk) {
                $values = [];
                foreach ($chunk as $fid => $s) $values[] = "(" . (int)$fid . ", " . (int)$s . ", UTC_TIMESTAMP(3))";
                $conn->exec("INSERT IGNORE INTO files_offline_folders (folder_id, state, updated_datetime) VALUES " . implode(',', $values));
            }
        });
    }

    // ── Copies ─────────────────────────────────────────────────────────

    /**
     * Deletes the copies under a folder (and below) or of a file that nothing covers any
     * more. Only keys with a recorded copy are looked at, in batches.
     *
     * @return int copies deleted
     */
    private static function tidyScope(PDO $conn, string $type, int $id): int
    {
        $where = $type === 'folder'
            ? 'i.folder_id IN (' . implode(',', array_map('intval', FilesAcl::descendants($conn, $id))) . ')'
            : 'i.id = ' . (int)$id;
        $cov = FilesOfflineCoverage::load($conn);
        $removed = 0;
        for ($after = 0; ; ) {
            $rows = $conn->query("SELECT i.id, v.storage_path FROM files_items i
                                    JOIN files_versions v ON v.id = i.current_version_id
                                    JOIN files_offline_copies c ON c.storage_path = v.storage_path
                                   WHERE $where AND i.id > " . (int)$after . " ORDER BY i.id LIMIT " . (int)self::$batch)->fetchAll(PDO::FETCH_NUM);
            if (!$rows) break;
            $after = (int)end($rows)[0];
            $keys = array_column($rows, 1);
            $covered = self::coveredKeys($conn, $cov, $keys);
            foreach (array_unique($keys) as $key) {
                if (!isset($covered[$key]) && self::forgetKey($conn, $key)) $removed++;
            }
        }
        return $removed;
    }

    /**
     * Which of these keys a live, kept file still uses as its current version: [key => true].
     * Nothing is covered while offline copies mean nothing (no S3-compatible storage).
     */
    private static function coveredKeys(PDO $conn, FilesOfflineCoverage $cov, array $keys): array
    {
        $keys = array_values(array_unique(array_filter($keys, 'filesStorageKeyIsValid')));
        if (!$keys || !$cov->any() || !filesOfflineApplies($conn)) return [];
        $in = implode(',', array_map([$conn, 'quote'], $keys));
        $out = [];
        foreach ($conn->query("SELECT i.id, i.folder_id, v.storage_path FROM files_items i
                                 JOIN files_versions v ON v.id = i.current_version_id
                                WHERE i.deleted_datetime IS NULL AND v.storage_path IN ($in)")->fetchAll(PDO::FETCH_NUM) as [$iid, $fid, $key]) {
            if (filesOfflineKept($cov->item((int)$iid, (int)$fid))) $out[(string)$key] = true;
        }
        return $out;
    }

    /**
     * Forgets a key's offline copy: deletes the file (and date folders left empty) and its
     * files_offline_copies row. Used when bytes are deleted for good (Overwrite, Delete
     * version, the versions tidy-up, the recycle bin) and when nothing covers it any more.
     * Never touches a store's own files (filesOfflineOverlapsStore).
     *
     * @return bool true when a copy was deleted
     */
    public static function forgetKey(PDO $conn, string $key): bool
    {
        $p = filesOfflinePath($conn, $key);
        if ($p === null || filesOfflineOverlapsStore($conn)) return false;
        $deleted = false;
        if (is_file($p)) {
            if (!@unlink($p)) {
                error_log("files offline: could not delete the copy {$key}");
                return false;
            }
            $deleted = true;
            self::removeEmptyFolders(filesOfflineRoot($conn), dirname($p));
        }
        try {
            $conn->prepare("DELETE FROM files_offline_copies WHERE storage_path = ?")->execute([$key]);
        } catch (PDOException $e) {
            if (!filesOfflineMissingTable($e)) throw $e;
        }
        return $deleted;
    }

    /** Records a complete copy of a key. */
    private static function recordReady(PDO $conn, string $key, int $size): void
    {
        $conn->prepare("INSERT INTO files_offline_copies (storage_path, size_bytes, state, failed_datetime, updated_datetime)
                        VALUES (?, ?, 'ready', NULL, UTC_TIMESTAMP())
                        ON DUPLICATE KEY UPDATE size_bytes = VALUES(size_bytes), state = 'ready', failed_datetime = NULL, updated_datetime = UTC_TIMESTAMP()")
             ->execute([$key, $size]);
    }

    /** Records that a key's copy failed for a reason of its own (tried again after RETRY_FAILED_AFTER). */
    private static function recordFailed(PDO $conn, string $key): void
    {
        $conn->prepare("INSERT INTO files_offline_copies (storage_path, size_bytes, state, failed_datetime, updated_datetime)
                        VALUES (?, 0, 'failed', UTC_TIMESTAMP(), UTC_TIMESTAMP())
                        ON DUPLICATE KEY UPDATE size_bytes = 0, state = 'failed', failed_datetime = UTC_TIMESTAMP(), updated_datetime = UTC_TIMESTAMP()")
             ->execute([$key]);
    }

    /** Removes $dir and the folders above it while they are empty, up to (not including) $root. */
    private static function removeEmptyFolders(string $root, string $dir): void
    {
        for ($d = $dir; strlen($d) > strlen($root); $d = dirname($d)) {
            if (!@rmdir($d)) break;
        }
    }

    /**
     * Copies one stored file to its offline place: read from wherever it lives now,
     * check, rename into place. Records nothing (the caller does).
     *
     * With a deadline (the job), the bytes are fetched into <copy>.part and the fetch
     * stops once the deadline passes, keeping what it has: the next run carries on from
     * there. So one very large file never holds a run past its time - it is copied over
     * several runs - and an outage part-way loses nothing either.
     *
     * @param ?int $deadlineUnix  stop fetching at this time (the job); null = no limit
     * @throws StorageUnavailable when the store cannot be reached
     * @throws FilesOfflineDiskFull when the copy would leave too little free disk, or cannot be written
     * @throws FilesOfflineOutOfTime when the deadline passed first (what was fetched is kept)
     * @throws RuntimeException when the copy does not match (size or SHA-256)
     */
    public static function copyKey(PDO $conn, string $key, int $size, ?string $sha, ?int $deadlineUnix = null): void
    {
        $final = filesOfflinePath($conn, $key);
        if ($final === null) throw new RuntimeException('Not a stored file.');
        $resume = $deadlineUnix !== null;
        $tmp = $resume ? self::partFor($final) : self::tmpFor($final);
        clearstatcache(true, $tmp);
        $have = $resume && is_file($tmp) ? (int)filesize($tmp) : 0;
        if ($have > $size) { @unlink($tmp); $have = 0; }   // not a beginning of this file
        $free = @disk_free_space(dirname($tmp));
        // Unknown free space (false) does not block: the write itself fails on a full disk.
        if ($free !== false && $free - ($size - $have) < self::$minFreeBytes) {
            throw new FilesOfflineDiskFull('Not enough free disk for offline copies (' . (int)$free . ' bytes free).');
        }
        $keep = false;   // leave the .part for the next run
        try {
            $fh = @fopen($tmp, $have > 0 ? 'ab' : 'wb');
            if (!$fh) throw new FilesOfflineDiskFull('The offline copy could not be written.');
            $outOfTime = false;
            $writeFailed = false;
            try {
                if ($have < $size) {
                    filesStoreFor($conn, $key)->readRange($key, $have, $size - 1, function (string $c) use ($fh, $deadlineUnix, &$outOfTime, &$writeFailed) {
                        if (fwrite($fh, $c) !== strlen($c)) { $writeFailed = true; return false; }
                        if ($deadlineUnix !== null && time() >= $deadlineUnix) { $outOfTime = true; return false; }
                        return true;
                    });
                }
                // fwrite is buffered: a full disk can also show up only here.
                if (!fflush($fh)) $writeFailed = true;
            } catch (StorageUnavailable $e) {
                $keep = $resume;   // an outage part-way: carry on from here next time
                throw $e;
            } finally {
                fclose($fh);
            }
            if ($writeFailed) throw new FilesOfflineDiskFull('The offline copy could not be written (is the disk full?).');
            clearstatcache(true, $tmp);
            $got = is_file($tmp) ? (int)filesize($tmp) : -1;
            if ($outOfTime && $got >= 0 && $got < $size) {
                $keep = true;
                throw new FilesOfflineOutOfTime("Out of time with {$got} of {$size} bytes copied.");
            }
            if ($got !== $size) throw new RuntimeException('copy did not match (size)');
            if ($sha !== null && $sha !== '' && !hash_equals(strtolower($sha), hash_file('sha256', $tmp))) {
                throw new RuntimeException('copy did not match (SHA-256)');
            }
            // On Windows a rename onto a copy someone has open fails. If another request
            // put the same copy there meanwhile, that is success.
            if (!@rename($tmp, $final) && !filesOfflineHasCopy($conn, $key, $size)) {
                throw new RuntimeException('could not move the copy into place');
            }
        } finally {
            if (!$keep && is_file($tmp)) @unlink($tmp);
        }
    }

    // ── Uploads ────────────────────────────────────────────────────────

    /**
     * Keeps a copy of a file being uploaded into a covered folder (or as a new version
     * of a kept file), under a temporary name. Called before the upload stores the part,
     * which may move it away; commitUploadCopy() puts it in place once the upload is
     * saved, so a failed upload leaves no copy (only a .tmp the job clears).
     *
     * The copy is a hard link when the part is on the same disk (instant, and it outlives
     * the part being moved or deleted); otherwise the bytes are copied only up to
     * $instantMaxBytes - a bigger upload is left to the job. Never throws.
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
            $cov = FilesOfflineCoverage::load($conn);
            if (!$cov->any()) return null;
            $state = $itemId !== null ? $cov->item($itemId, $folderId) : $cov->folder($folderId);
            if (!filesOfflineKept($state)) return null;   // not kept, or left out
            $tmp = self::uploadCopy($conn, $partPath, $key);
            // No copy kept: the folder's tick says "being made available" until the job copies it.
            if ($tmp === null) self::rollupPending($conn, [$folderId]);
            return $tmp;
        } catch (Throwable $e) {
            error_log("files offline: could not keep a copy of the upload {$key}: " . $e->getMessage());
            return null;
        }
    }

    /** keepUploadCopy()'s copy: a hard link, or a copy up to $instantMaxBytes, within the limit and the free-disk floor. */
    private static function uploadCopy(PDO $conn, string $partPath, string $key): ?string
    {
        $final = filesOfflinePath($conn, $key);
        if ($final === null) return null;
        $size = (int)@filesize($partPath);
        // The administrator's limit: past it the job leaves the file and says so on the Storage tab.
        $limit = filesOfflineLimit($conn);
        if ($limit !== null && (int)(filesOfflineUsage($conn)['bytes'] ?? 0) + $size > $limit) return null;
        $tmp = self::tmpFor($final);
        // The same floor as the job: copies share the disk with uploads in progress.
        $free = @disk_free_space(dirname($tmp));
        if ($free !== false && $free - $size < self::$minFreeBytes) {
            error_log("files offline: not enough free disk to keep a copy of the upload {$key} (the job will retry)");
            return null;
        }
        if (@link($partPath, $tmp)) return $tmp;
        if ($size > self::$instantMaxBytes) return null;   // the job copies it from S3
        if (!@copy($partPath, $tmp)) {
            @unlink($tmp);
            error_log("files offline: could not keep a copy of the upload {$key} (the job will retry)");
            return null;
        }
        return $tmp;
    }

    /**
     * Puts an upload's temporary copy (from keepUploadCopy) in place, after the upload is
     * saved, and records it. Never throws.
     *
     * @param ?string $tmp       what keepUploadCopy() returned; null does nothing
     * @param ?int    $folderId  the folder uploaded into: its tick says pending if the copy does not land
     */
    public static function commitUploadCopy(PDO $conn, ?string $tmp, string $key, ?int $folderId = null): void
    {
        if ($tmp === null) return;
        try {
            $final = filesOfflinePath($conn, $key);
            if ($final === null || (!@rename($tmp, $final) && !is_file($final))) {
                error_log("files offline: could not keep a copy of the upload {$key} (the job will retry)");
                if ($folderId !== null) self::foldersChanged($conn, [$folderId]);
            } else {
                // Dated now, not when the part was copied: a job run that started before
                // the upload was saved must not take it for a stale copy.
                @touch($final);
                clearstatcache(true, $final);
                self::recordReady($conn, $key, (int)filesize($final));
            }
        } catch (Throwable $e) {
            error_log("files offline: could not keep a copy of the upload {$key}: " . $e->getMessage());
        } finally {
            if (is_file($tmp)) @unlink($tmp);
        }
    }

    // ── The storage folder changed ─────────────────────────────────────

    /**
     * The local storage folder changed (Files -> Settings -> Storage). Called inside the
     * save's transaction, so it only writes rows. When the two are PROVED to be different
     * places the recorded copies (they were under the old folder) are forgotten and the
     * old folder is queued for the job, which deletes its copies in batches after the
     * commit (files_offline_old_roots). 'same' keeps everything. 'unknown' keeps the
     * records (the job forgets any whose file is not under the new folder) and queues
     * the old folder as UNPROVEN: never deleted by itself - the Storage tab offers Remove,
     * which probes again first (removeOldRoot). "Cannot tell" is never "different".
     *
     * @param string $relation  storageLocationRelation() of the two folders, or 'none'
     *                          when the old folder holds no offline copies
     */
    public static function storageFolderChanged(PDO $conn, string $oldRoot, string $newRoot, string $relation): void
    {
        $oldRoot = rtrim(str_replace('\\', '/', $oldRoot), '/');
        $newRoot = rtrim(str_replace('\\', '/', $newRoot), '/');
        if ($oldRoot === '' || $oldRoot === $newRoot || $relation === 'same' || $relation === 'none') return;
        if ($relation === 'different') {
            try {
                $conn->exec("DELETE FROM files_offline_copies");
            } catch (PDOException $e) {
                if (!filesOfflineMissingTable($e)) throw $e;
            }
        }
        if (str_starts_with($newRoot . '/', $oldRoot . '/offline/')) return;   // the new folder is inside the old copies
        $roots = array_filter(self::oldRoots($conn), fn($r) => $r['root'] !== $oldRoot);
        $roots[] = ['root' => $oldRoot, 'proven' => $relation === 'different'];
        self::saveOldRoots($conn, array_values($roots));
    }

    /**
     * Old storage folders that may still hold offline copies: [['root' => path, 'proven'
     * => true when proved to be another place - the job deletes those - or false]].
     */
    public static function oldRoots(PDO $conn): array
    {
        $v = json_decode(filesSetting($conn, 'files_offline_old_roots'), true);
        $out = [];
        foreach (is_array($v) ? $v : [] as $r) {
            if (is_array($r) && is_string($r['root'] ?? null)) $out[] = ['root' => $r['root'], 'proven' => !empty($r['proven'])];
        }
        return $out;
    }

    private static function saveOldRoots(PDO $conn, array $roots): void
    {
        filesSaveSetting($conn, 'files_offline_old_roots', $roots ? json_encode($roots) : null);
        FilesStorageCache::$settings['files_offline_old_roots'] = $roots ? json_encode($roots) : null;
    }

    /**
     * "Remove" for an old storage folder that could not be proved to be another place
     * (Files -> Settings -> Storage, Cap::FILES_STORAGE - the caller checks it). Probes
     * again: proved different, the job deletes its copies; the same place, it is
     * forgotten and nothing is deleted; still unknown, it is refused.
     *
     * @return array ['result' => 'queued' | 'same' | 'gone']
     */
    public static function removeOldRoot(PDO $conn, int $analystId, string $root): array
    {
        self::needAnalyst($analystId);
        return self::locked($conn, fn() => self::removeOldRootLocked($conn, $analystId, $root));
    }

    /** removeOldRoot(), holding the lock: the list is read, changed and saved in one go. */
    private static function removeOldRootLocked(PDO $conn, int $analystId, string $root): array
    {
        unset(FilesStorageCache::$settings['files_offline_old_roots']);   // read it fresh, now that nobody else is changing it
        $roots = self::oldRoots($conn);
        $match = array_values(array_filter($roots, fn($r) => $r['root'] === $root));
        if (!$match) throw new InvalidArgumentException('That folder is not waiting to be removed.');
        $current = rtrim(dirname(filesOfflineRoot($conn)), '/');
        $result = 'gone';
        if (is_dir($root . '/offline') && $root !== $current) {
            try {
                $rel = storageLocationRelation(new LocalDriver($root), new LocalDriver($current));
            } catch (Throwable $e) {
                $rel = 'unknown';
            }
            if ($rel === 'unknown') {
                throw new InvalidArgumentException('It still cannot be told whether ' . $root . ' is a different place from the current storage folder, so nothing was removed.');
            }
            $result = $rel === 'different' ? 'queued' : 'same';
        }
        $left = array_values(array_filter($roots, fn($r) => $r['root'] !== $root));
        if ($result === 'queued') $left[] = ['root' => $root, 'proven' => true];
        self::saveOldRoots($conn, $left);
        filesAudit($conn, $analystId, 'settings', ['path' => '(Settings: storage)'], ['offline_old_folder' => $root, 'result' => $result]);
        return ['result' => $result];
    }

    // ── The job ────────────────────────────────────────────────────────

    /**
     * The job: forget marks on things deleted for good, empty old storage folders, fill
     * missing copies, remove copies nothing covers (all of them when no S3-compatible
     * storage is in use) and files no row records. Everything is read in batches, so
     * memory does not grow with the number of files. Stops at $deadlineUnix, also in the
     * middle of a big copy (the next run carries on).
     *
     * @return array ['copied', 'removed', 'failed', 'skipped', 'marks_dropped' => int,
     *               'done' => bool, 'disk_full' => bool, 'limit_reached' => bool]
     */
    public static function sync(PDO $conn, int $deadlineUnix): array
    {
        $r = ['copied' => 0, 'removed' => 0, 'failed' => 0, 'skipped' => 0, 'marks_dropped' => 0,
              'done' => true, 'disk_full' => false, 'limit_reached' => false];
        if (filesOfflineMarks($conn) === null) return $r;   // before Database Verification: nothing was ever marked
        $started = time();
        $startedDb = (string)$conn->query("SELECT UTC_TIMESTAMP()")->fetchColumn();

        self::locked($conn, function () use ($conn, &$r) {
            $r['marks_dropped'] = $conn->exec("DELETE o FROM files_offline o LEFT JOIN files_folders f ON f.id = o.target_id
                                                WHERE o.target_type = 'folder' AND f.id IS NULL")
                                + $conn->exec("DELETE o FROM files_offline o LEFT JOIN files_items i ON i.id = o.target_id
                                                WHERE o.target_type = 'item' AND i.id IS NULL");
            $r['marks_dropped'] += self::dropUncoveredExclusions($conn);
        });
        self::emptyOldRoots($conn, $deadlineUnix, $r);
        if (filesOfflineOverlapsStore($conn)) {
            // The offline folder is a store's own folder (storage moved from <P>/offline to
            // <P>): what is in it is real stored files. Do nothing until that is over.
            error_log('files offline: the offline folder is also a storage folder - nothing copied or removed until that changes.');
            return $r;
        }
        // Records first (what nothing covers goes, a copy gone from disk is forgotten), so
        // the fill that follows makes good anything missing in the same run.
        self::tidyRows($conn, $deadlineUnix, $startedDb, $r);
        if (filesOfflineApplies($conn)) self::fill($conn, $deadlineUnix, $r);
        self::tidyDisk($conn, $deadlineUnix, $started, $r);
        self::rollup($conn);   // the folders' ticks: one grouped query, also after the deadline
        return $r;
    }

    /** Fills missing copies, in id order, a batch at a time. */
    private static function fill(PDO $conn, int $deadlineUnix, array &$r): void
    {
        $cov = FilesOfflineCoverage::load($conn);
        $cand = $cov->candidateSql();
        if ($cand === null) { filesSaveSetting($conn, 'files_offline_limit_reached', null); return; }
        $stateSql = filesOfflineStateSql($conn);
        if ($stateSql === null) { $r['done'] = false; return; }   // cannot tell what is local: next run
        $limit = filesOfflineLimit($conn);
        $used = (int)(filesOfflineUsage($conn)['bytes'] ?? 0);
        $finished = false;
        for ($after = 0, $stop = false; !$stop; ) {
            if (time() >= $deadlineUnix) { $r['done'] = false; break; }
            $rows = $conn->query("SELECT i.id, i.folder_id, v.storage_path, v.size_bytes, v.sha256, $stateSql
                                    FROM files_items i JOIN files_versions v ON v.id = i.current_version_id
                               LEFT JOIN files_offline_copies c ON c.storage_path = v.storage_path
                                   WHERE i.deleted_datetime IS NULL AND i.id > " . (int)$after . " AND $cand
                                ORDER BY i.id LIMIT " . (int)self::$batch)->fetchAll(PDO::FETCH_NUM);
            if (!$rows) { $finished = true; break; }
            foreach ($rows as [$iid, $fid, $key, $size, $sha, $st]) {
                $after = (int)$iid;
                $key = (string)$key; $size = (int)$size;
                if ((int)$st === 0 || !filesStorageKeyIsValid($key) || !filesOfflineKept($cov->item((int)$iid, (int)$fid))) continue;
                if ((int)$st === 1) { $r['skipped']++; continue; }   // failed: waiting out its day
                if (filesOfflineHasCopy($conn, $key, $size)) { self::recordReady($conn, $key, $size); continue; }   // shared bytes, copied just now
                if (time() >= $deadlineUnix) { $r['done'] = false; $stop = true; break; }
                if ($limit !== null && $used + $size > $limit) {
                    $r['limit_reached'] = true; $r['done'] = false; $stop = true;
                    break;
                }
                try {
                    self::copyKey($conn, $key, $size, $sha !== null ? (string)$sha : null, $deadlineUnix);
                    self::recordReady($conn, $key, $size);
                    $used += $size;
                    $r['copied']++;
                } catch (FilesOfflineOutOfTime $e) {
                    // A big file: what was fetched is kept, the next run carries on from there.
                    $r['done'] = false; $stop = true;
                    break;
                } catch (StorageUnavailable $e) {
                    // An outage: every other copy would fail the same way. Try next run.
                    error_log('files offline: storage unavailable, copying stopped: ' . $e->getMessage());
                    $r['failed']++; $r['done'] = false; $stop = true;
                    break;
                } catch (FilesOfflineDiskFull $e) {
                    error_log('files offline: copying stopped: ' . $e->getMessage());
                    $r['failed']++; $r['done'] = false; $r['disk_full'] = true; $stop = true;
                    break;
                } catch (Throwable $e) {
                    // This file's own problem (missing in S3, not matching): skipped for a day.
                    error_log("files offline: could not copy {$key} (tried again in a day): " . $e->getMessage());
                    self::recordFailed($conn, $key);
                    $r['skipped']++;
                }
            }
        }
        // The Storage tab says when the limit stopped the copying; a full pass clears it.
        if ($r['limit_reached']) filesSaveSetting($conn, 'files_offline_limit_reached', '1');
        elseif ($finished) filesSaveSetting($conn, 'files_offline_limit_reached', null);
    }

    /**
     * Goes through the recorded copies a batch at a time: removes those nothing covers
     * (unless recorded after this run started), and
     * forgets ready rows whose file is gone or the wrong size (the next run copies again).
     */
    private static function tidyRows(PDO $conn, int $deadlineUnix, string $startedDb, array &$r): void
    {
        for ($lastId = 0; ; ) {
            if (time() >= $deadlineUnix) { $r['done'] = false; return; }
            $rows = $conn->query("SELECT id, storage_path, size_bytes, state, updated_datetime <= " . $conn->quote($startedDb) . "
                                    FROM files_offline_copies WHERE id > " . (int)$lastId . " ORDER BY id LIMIT " . (int)self::$batch)->fetchAll(PDO::FETCH_NUM);
            if (!$rows) return;
            $lastId = (int)end($rows)[0];
            self::locked($conn, function () use ($conn, $rows, &$r) {
                $covered = self::coveredKeys($conn, FilesOfflineCoverage::load($conn), array_column($rows, 1));
                foreach ($rows as [$id, $key, $size, $state, $old]) {
                    $key = (string)$key;
                    if (!isset($covered[$key])) {
                        if ((int)$old === 1 && self::forgetKey($conn, $key)) $r['removed']++;
                        continue;
                    }
                    if ($state === 'ready' && !filesOfflineHasCopy($conn, $key, (int)$size)) {
                        $p = filesOfflinePath($conn, $key);
                        if ($p !== null && is_file($p)) @unlink($p);   // the wrong size: never served, made again
                        $conn->prepare("DELETE FROM files_offline_copies WHERE id = ?")->execute([(int)$id]);
                    }
                }
            });
        }
    }

    /**
     * Walks the offline folder as a stream, a batch of names at a time: deletes copies no
     * row records (older than this run), temporary copies older than a day, and part-way
     * copies whose file has a copy, is no longer kept, or has not grown for a day.
     */
    private static function tidyDisk(PDO $conn, int $deadlineUnix, int $started, array &$r): void
    {
        $root = filesOfflineRoot($conn);
        if (!is_dir($root)) return;
        $cov = null;
        $batch = [];   // [key => [[path, 'copy'|'part'], ...]]
        $flush = function () use ($conn, &$batch, &$cov, $started, &$r, $root) {
            if (!$batch) return;
            $keys = array_keys($batch);
            $in = implode(',', array_map([$conn, 'quote'], $keys));
            $ready = [];
            foreach ($conn->query("SELECT storage_path FROM files_offline_copies WHERE state = 'ready' AND storage_path IN ($in)")->fetchAll(PDO::FETCH_COLUMN) as $k) $ready[(string)$k] = true;
            $cov ??= FilesOfflineCoverage::load($conn);
            $covered = self::coveredKeys($conn, $cov, $keys);
            foreach ($batch as $key => $files) {
                foreach ($files as [$path, $kind]) {
                    clearstatcache(true, $path);
                    $mtime = (int)@filemtime($path);
                    $gone = $kind === 'copy'
                        ? !isset($ready[$key]) && $mtime < $started
                        : isset($ready[$key]) || !isset($covered[$key]) || $mtime < time() - self::TMP_MAX_AGE;
                    if ($gone && @unlink($path)) {
                        if ($kind === 'copy') $r['removed']++;
                        self::removeEmptyFolders($root, dirname($path));
                    }
                }
            }
            $batch = [];
        };
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (time() >= $deadlineUnix) { $r['done'] = false; break; }
            if (!$f->isFile()) continue;
            $path = str_replace('\\', '/', $f->getPathname());
            $rel = substr($path, strlen($root) + 1);
            if (str_ends_with($rel, '.tmp')) {
                if (@filemtime($path) < time() - self::TMP_MAX_AGE) @unlink($path);
                continue;
            }
            if (filesStorageKeyIsValid($rel)) $batch[$rel][] = [$path, 'copy'];
            elseif (str_ends_with($rel, '.part') && filesStorageKeyIsValid(substr($rel, 0, -5))) $batch[substr($rel, 0, -5)][] = [$path, 'part'];
            if (count($batch) >= self::$batch) $flush();
        }
        $flush();
    }

    /**
     * Deletes the copies left under old storage folders (storageFolderChanged), streaming,
     * until the deadline; a folder emptied is dropped from the list. Only files named like
     * copies are touched, and never a folder that is a store's own.
     */
    private static function emptyOldRoots(PDO $conn, int $deadlineUnix, array &$r): void
    {
        $roots = self::oldRoots($conn);
        if (!$roots) return;
        $current = rtrim(dirname(filesOfflineRoot($conn)), '/');
        $left = [];
        foreach ($roots as $entry) {
            if (!$entry['proven']) { $left[] = $entry; continue; }   // never deleted without proof
            $old = $entry['root'];
            $dir = $old . '/offline';
            if ($old === $current || !is_dir($dir)) continue;   // nothing (more) to do
            if (filesOfflineOverlapsStore($conn, $dir)) continue;   // real stored files now: never delete
            $finished = true;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $f) {
                if (time() >= $deadlineUnix) { $finished = false; $r['done'] = false; break; }
                $path = str_replace('\\', '/', $f->getPathname());
                if ($f->isDir()) { @rmdir($path); continue; }   // only once empty
                $rel = substr($path, strlen($dir) + 1);
                if ((filesStorageKeyIsValid($rel) || filesOfflineIsTmp($rel)) && @unlink($path)) $r['removed']++;
            }
            if ($finished) @rmdir($dir);
            else $left[] = $entry;
        }
        if ($left === $roots) return;
        // Saved under the lock against a fresh read: a folder queued, proved or removed
        // meanwhile (a storage change, Remove) is kept as it now is.
        $done = array_column(array_udiff($roots, $left, fn($a, $b) => strcmp(json_encode($a), json_encode($b))), 'root');
        self::locked($conn, function () use ($conn, $done) {
            unset(FilesStorageCache::$settings['files_offline_old_roots']);
            $now = self::oldRoots($conn);
            $keep = array_values(array_filter($now, fn($r) => !($r['proven'] && in_array($r['root'], $done, true))));
            if ($keep !== $now) self::saveOldRoots($conn, $keep);
        });
    }

    /** Where the job keeps a copy it is part-way through, beside $final, its folders created. */
    private static function partFor(string $final): string
    {
        $dir = dirname($final);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new RuntimeException('The offline folder could not be created.');
        }
        return $final . '.part';
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
