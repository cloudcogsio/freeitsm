<?php
/**
 * Files - offline copies ("Make available offline").
 *
 * When Files is stored in S3-compatible storage, a file or folder can be marked so
 * that a copy of its bytes is kept on the server too, at
 * <storage root>/offline/<key>. Reads use that copy first (filesServeBytes), so the
 * file opens fast and still opens while S3 cannot be reached. S3 stays the master.
 *
 * Marks live in files_offline (target_type folder|item, marked_by). What is COVERED:
 * the current version of every live file that is marked itself or sits, at any
 * depth, under a marked live folder - so files uploaded later and new subfolders
 * are covered too - BUT ONLY WHAT THE PERSON WHO MADE THE MARK CAN SEE, through their
 * own Files permissions, checked every time: a folder further down that stops
 * inheriting and is closed to them is not copied, and someone who loses access stops
 * covering it. A mark whose maker is no longer an active analyst covers nothing (the
 * mark stays: anyone with Modify can make it again, as theirs). The background job
 * never copies anything the person could not have opened by hand.
 *
 * A mark with excluded = 1 ("Don't keep offline") leaves a file or a folder out of a
 * folder kept offline: THE NEAREST MARK WINS, as permissions inherit - a folder marked
 * inside an excluded one is kept again. Things in the recycle bin are not covered
 * (their marks stay and apply again after a restore). Older versions are not kept.
 *
 * The copies themselves are recorded in files_offline_copies (one row per stored key:
 * 'ready' with its size, or 'failed' with when), written by the service and the job,
 * so every question about them is one SQL query - never a walk of the disk or of
 * every covered file. Copies share keys exactly as files_versions rows do (a copied
 * file shares its source's stored bytes). Keys are never rewritten (a new version gets
 * a new key), so a copy with the right size holds the right bytes.
 *
 * Writes (marking, filling, removing) are in includes/services/files_offline.php.
 */

require_once __DIR__ . '/storage.php';
require_once __DIR__ . '/acl.php';

/** A file whose copy failed for a reason of its own is tried again after this long (seconds). */
const FILES_OFFLINE_RETRY_AFTER = 86400;

/** True when a PDOException means a table does not exist (before Database Verification). */
function filesOfflineMissingTable(PDOException $e): bool
{
    return ($e->errorInfo[1] ?? null) === 1146 || $e->getCode() === '42S02';
}

/**
 * Every mark: ['folder' => [id => marked_by], 'item' => [id => marked_by], 'exclude' =>
 * ['folder' => [id => true], 'item' => [id => true]]] - 'folder' and 'item' keep things
 * offline (marked_by 0 when nobody is recorded), 'exclude' leaves them out of a folder
 * kept offline. null when files_offline does not exist yet (before Database
 * Verification): nothing can have been marked then. Any other database error is thrown.
 */
function filesOfflineMarks(PDO $conn): ?array
{
    try {
        $rows = $conn->query("SELECT target_type, target_id, excluded, marked_by FROM files_offline")->fetchAll(PDO::FETCH_NUM);
    } catch (PDOException $e) {
        if (filesOfflineMissingTable($e)) return null;
        throw $e;
    }
    $out = ['folder' => [], 'item' => [], 'exclude' => ['folder' => [], 'item' => []]];
    foreach ($rows as [$type, $id, $ex, $by]) {
        if (!isset($out[$type])) continue;
        if ((int)$ex === 1) $out['exclude'][$type][(int)$id] = true;
        else $out[$type][(int)$id] = (int)$by;
    }
    return $out;
}

/** True for a coverage state that keeps something offline ('self' or 'folder'). */
function filesOfflineKept(?string $state): bool
{
    return $state === 'self' || $state === 'folder';
}

/**
 * What the marks cover, worked out over the folder tree (never over files): for each
 * live folder, and on request each file, 'self' (marked itself), 'folder' (kept by a
 * folder above), 'excluded' (left out of a folder kept offline) or null. A mark covers
 * only what its maker can see (FilesAcl::levels of marked_by) while they are an active
 * analyst.
 */
final class FilesOfflineCoverage
{
    private array $tree;
    /** [folderId => ?string] */
    private array $state = [];
    /** [analystId => levels map, or [] when inactive or unknown] */
    private array $levels = [];
    /** [analystId => true when an active analyst] */
    private array $active = [];

    public function __construct(private PDO $conn, private ?array $marks)
    {
        $this->tree = FilesAcl::tree($conn);
    }

    /** Reads the marks now; null marks (before Database Verification) cover nothing. */
    public static function load(PDO $conn): self
    {
        return new self($conn, filesOfflineMarks($conn));
    }

    public function marks(): ?array
    {
        return $this->marks;
    }

    /** True when there is any mark that keeps something offline. */
    public function any(): bool
    {
        return $this->marks !== null && ($this->marks['folder'] || $this->marks['item']);
    }

    /** True when $analystId is an active analyst who can see $folderId. */
    public function markerSees(int $analystId, int $folderId): bool
    {
        if ($analystId <= 0) return false;
        if (!array_key_exists($analystId, $this->levels)) {
            $st = $this->conn->prepare("SELECT is_active FROM analysts WHERE id = ?");
            $st->execute([$analystId]);
            $this->active[$analystId] = (int)$st->fetchColumn() === 1;
            $this->levels[$analystId] = $this->active[$analystId] ? FilesAcl::levels($this->conn, $analystId) : [];
        }
        return ($this->levels[$analystId][$folderId] ?? FilesAcl::NONE) >= FilesAcl::VIEW;
    }

    /**
     * A live folder's state: 'self', 'folder', 'excluded' or null. Walks up from the
     * folder: the nearest EFFECTIVE keep mark decides - one whose maker is active and
     * can see this folder; a mark that is not effective here is passed over, and the
     * next one above counts (so a folder kept by Alice stays kept when Bob, who marked
     * a subfolder of it, is deactivated or cannot see it). "Don't keep offline" marks
     * between the folder and that keep mark leave it out; 'excluded' is shown on the
     * folder left out itself, when it is the only one in between.
     */
    public function folder(int $id): ?string
    {
        if (array_key_exists($id, $this->state)) return $this->state[$id];
        if (!$this->marks || !isset($this->tree[$id])) return $this->state[$id] = null;
        $exclusions = [];
        for ($a = $id, $depth = 0; $a !== null && isset($this->tree[$a]) && $depth < 1000; $a = $this->tree[$a]['parent_id'], $depth++) {
            if (isset($this->marks['folder'][$a])) {
                if (!$this->markerSees($this->marks['folder'][$a], $id)) continue;   // not effective here: the next one above counts
                if (!$exclusions) return $this->state[$id] = $a === $id ? 'self' : 'folder';
                return $this->state[$id] = $exclusions === [$id] ? 'excluded' : null;
            }
            if (isset($this->marks['exclude']['folder'][$a])) $exclusions[] = $a;
        }
        return $this->state[$id] = null;   // no effective mark: an exclusion alone means nothing
    }

    /** A live file's state: 'self', 'folder', 'excluded' or null. Its own mark counts only while effective. */
    public function item(int $itemId, int $folderId): ?string
    {
        if (!$this->marks || !isset($this->tree[$folderId])) return null;   // its folder is in the recycle bin
        if (isset($this->marks['item'][$itemId]) && $this->markerSees($this->marks['item'][$itemId], $folderId)) return 'self';
        $kept = filesOfflineKept($this->folder($folderId));
        if (isset($this->marks['exclude']['item'][$itemId])) return $kept ? 'excluded' : null;
        return $kept ? 'folder' : null;
    }

    /** True when a mark's maker is no longer an active analyst (or none is recorded). */
    public function markerInactive(int $analystId): bool
    {
        if ($analystId <= 0) return true;
        $this->markerSees($analystId, 0);   // loads them
        return $this->active[$analystId] === false;
    }
    /** The live folders whose files are kept offline (state 'self' or 'folder'). */
    public function keptFolderIds(): array
    {
        if (!$this->any()) return [];
        $out = [];
        foreach ($this->tree as $id => $_) if (filesOfflineKept($this->folder($id))) $out[] = $id;
        return $out;
    }

    /** The files marked themselves (to be checked with item()). */
    public function markedItemIds(): array
    {
        return $this->marks ? array_keys($this->marks['item']) : [];
    }

    /** Every file with a mark of its own, kept or left out. */
    public function itemMarkIds(): array
    {
        return $this->marks ? array_keys($this->marks['item'] + $this->marks['exclude']['item']) : [];
    }

    /**
     * The SQL condition (alias i = files_items) for files that MAY be covered: in a kept
     * folder, or marked themselves. Rows still go through item() - it applies "left out"
     * and the maker's permissions. null when nothing can be covered.
     */
    public function candidateSql(): ?string
    {
        $where = [];
        // Ids are written in as integers rather than placeholders: a big tree can cover more
        // folders than a prepared statement allows placeholders (65,535).
        if ($f = $this->keptFolderIds())   $where[] = 'i.folder_id IN (' . implode(',', array_map('intval', $f)) . ')';
        if ($m = $this->markedItemIds())  $where[] = 'i.id IN (' . implode(',', array_map('intval', $m)) . ')';
        return $where ? '(' . implode(' OR ', $where) . ')' : null;
    }

    /** The live tree (FilesAcl::tree). */
    public function tree(): array
    {
        return $this->tree;
    }
}

/**
 * SQL that is true when a stored file (alias v = files_versions) is already stored in a
 * folder on this server - during a move from S3 back to a folder, once the move has
 * verified it. Its bytes are here, so it needs no copy and counts as available offline.
 * null when the storage settings cannot be read (the answer is unknown).
 */
function filesOfflineLocalSql(PDO $conn): ?string
{
    try {
        $activeLocal = filesActiveStore($conn) instanceof LocalDriver;
        $prev = filesPreviousStore($conn);
    } catch (Throwable $e) {
        error_log('files offline: storage settings could not be read: ' . $e->getMessage());
        return null;
    }
    if ($prev === null || ($prev instanceof LocalDriver) === $activeLocal) return $activeLocal ? '1' : '0';
    // During a move a key is read from the old place until the move has verified it (filesStoreFor).
    $old = "EXISTS (SELECT 1 FROM storage_migration_items m WHERE m.store = 'files' AND m.object_key = v.storage_path"
         . " AND m.state NOT IN ('verified', 'removed'))";
    return $activeLocal ? "NOT $old" : $old;
}

/**
 * SQL for where a covered file stands (alias v = files_versions, c = a LEFT JOIN of
 * files_offline_copies on storage_path): 0 ready (a complete copy, or stored here
 * already), 1 failed (tried again after FILES_OFFLINE_RETRY_AFTER), 2 pending.
 * null when that cannot be worked out.
 */
function filesOfflineStateSql(PDO $conn): ?string
{
    $local = filesOfflineLocalSql($conn);
    if ($local === null) return null;
    return "(CASE WHEN (c.state = 'ready' AND c.size_bytes = v.size_bytes) OR ($local) THEN 0"
         . " WHEN c.state = 'failed' AND c.failed_datetime > UTC_TIMESTAMP() - INTERVAL " . FILES_OFFLINE_RETRY_AFTER . " SECOND THEN 1"
         . " ELSE 2 END)";
}

/** The status words for the numbers filesOfflineStateSql() gives. */
const FILES_OFFLINE_STATUS = [0 => 'ready', 1 => 'failed', 2 => 'pending'];

/**
 * Where each of these live files stands: [itemId => 'ready' | 'failed' | 'pending' |
 * 'unknown' (could not be worked out)]. One query.
 *
 * @param int[] $itemIds
 */
function filesOfflineItemStates(PDO $conn, array $itemIds): array
{
    if (!$itemIds) return [];
    $sql = filesOfflineStateSql($conn);
    if ($sql === null) return array_fill_keys($itemIds, 'unknown');
    $st = $conn->query("SELECT i.id, $sql FROM files_items i JOIN files_versions v ON v.id = i.current_version_id
                          LEFT JOIN files_offline_copies c ON c.storage_path = v.storage_path
                         WHERE i.id IN (" . implode(',', array_map('intval', $itemIds)) . ")");
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_NUM) as [$id, $s]) $out[(int)$id] = FILES_OFFLINE_STATUS[(int)$s];
    return $out;
}

/**
 * Where the covered files directly in each folder stand, for the job to store in
 * files_offline_folders: [folderId => 0 ready | 1 failed | 2 pending] for every kept
 * folder (0 when it holds no files) and every folder holding a file kept by its own
 * mark. One grouped query over the covered files - the job's work, never a page's.
 * null when it cannot be worked out (the storage settings cannot be read).
 */
function filesOfflineFolderRollup(PDO $conn, FilesOfflineCoverage $cov): ?array
{
    $sql = filesOfflineStateSql($conn);
    if ($sql === null) return null;
    $kept = $cov->keptFolderIds();
    $out = array_fill_keys($kept, 0);
    // Files with a mark of their own: left out (not counted), or kept in a folder that is not.
    $leftOut = []; $own = [];
    if ($ids = $cov->itemMarkIds()) {
        $st = $conn->query("SELECT id, folder_id FROM files_items WHERE deleted_datetime IS NULL AND id IN (" . implode(',', array_map('intval', $ids)) . ")");
        foreach ($st->fetchAll(PDO::FETCH_NUM) as [$iid, $fid]) {
            $kf = isset($out[(int)$fid]);
            $ki = filesOfflineKept($cov->item((int)$iid, (int)$fid));
            if ($kf && !$ki) $leftOut[] = (int)$iid;
            elseif (!$kf && $ki) $own[] = (int)$iid;
        }
    }
    $from = "FROM files_items i JOIN files_versions v ON v.id = i.current_version_id
             LEFT JOIN files_offline_copies c ON c.storage_path = v.storage_path WHERE i.deleted_datetime IS NULL";
    $rows = [];
    if ($kept) {
        $rows = $conn->query("SELECT i.folder_id, MAX($sql) $from AND i.folder_id IN (" . implode(',', array_map('intval', $kept)) . ")"
                             . ($leftOut ? " AND i.id NOT IN (" . implode(',', $leftOut) . ")" : '') . " GROUP BY i.folder_id")->fetchAll(PDO::FETCH_NUM);
    }
    if ($own) {
        $rows = array_merge($rows, $conn->query("SELECT i.folder_id, MAX($sql) $from AND i.id IN (" . implode(',', $own) . ") GROUP BY i.folder_id")->fetchAll(PDO::FETCH_NUM));
    }
    foreach ($rows as [$fid, $s]) $out[(int)$fid] = max($out[(int)$fid] ?? 0, (int)$s);
    return $out;
}

/**
 * How far the copies under folders kept offline have got, as THIS VIEWER may know it:
 * [folderId => 'ready' | 'pending' | 'failed'] for each of $folderIds that is kept.
 * Only subfolders the viewer can see count - a folder closed to them never shows
 * through. 'pending' while any covered file under it still waits for its copy,
 * otherwise 'failed' while one could not be copied, otherwise 'ready'.
 *
 * Read from files_offline_folders, which the job keeps (one row per folder, written at
 * the end of every run) and the service marks pending when it adds something to copy:
 * one indexed lookup of the viewer's folders below those on screen, never the files.
 * A kept folder without a row has not been worked out yet: pending.
 *
 * @param array $viewerLevels  FilesAcl::levels() of the viewer
 * @param int[] $folderIds     the folders on screen
 */
function filesOfflineFolderStates(PDO $conn, FilesOfflineCoverage $cov, array $viewerLevels, array $folderIds): array
{
    $out = [];
    foreach ($folderIds as $id) if (filesOfflineKept($cov->folder((int)$id))) $out[(int)$id] = 0;
    if (!$out) return [];

    // The viewer's folders under each one on screen: [folderId => [folders on screen above it]].
    $children = [];
    foreach ($cov->tree() as $fid => $f) if ($f['parent_id'] !== null) $children[$f['parent_id']][] = $fid;
    $owners = [];
    foreach (array_keys($out) as $top) {
        $stack = [$top];
        while ($stack) {
            $fid = array_pop($stack);
            if (($viewerLevels[$fid] ?? FilesAcl::NONE) >= FilesAcl::VIEW) $owners[$fid][] = $top;
            foreach ($children[$fid] ?? [] as $c) $stack[] = $c;
        }
    }
    $rolled = [];
    foreach ($conn->query("SELECT folder_id, state FROM files_offline_folders WHERE folder_id IN (" . implode(',', array_keys($owners)) . ")")->fetchAll(PDO::FETCH_NUM) as [$fid, $s]) {
        $rolled[(int)$fid] = (int)$s;
    }
    foreach ($owners as $fid => $tops) {
        $s = $rolled[$fid] ?? (filesOfflineKept($cov->folder($fid)) ? 2 : null);   // kept, not worked out yet: pending
        if ($s === null) continue;
        foreach ($tops as $top) if ($s > $out[$top]) $out[$top] = $s;   // ready < failed < pending
    }
    return array_map(fn($s) => FILES_OFFLINE_STATUS[$s], $out);
}
/**
 * The coverage to SHOW (badges, Properties): null when offline copies mean nothing
 * (Files stored in a server folder - marks are kept but have no effect, and the menu is
 * hidden, so a badge would only mislead) or before Database Verification.
 */
function filesOfflineDisplayCoverage(PDO $conn): ?FilesOfflineCoverage
{
    if (!filesOfflineApplies($conn)) return null;
    $cov = FilesOfflineCoverage::load($conn);
    return $cov->marks() === null ? null : $cov;
}

/**
 * Where offline copies live: <storage root>/offline. Creates nothing - not even the
 * storage root (every S3 download asks, also on installs that never used this).
 */
function filesOfflineRoot(PDO $conn): string
{
    return rtrim(str_replace('\\', '/', filesSetting($conn, 'files_storage_root', filesDefaultStorageRoot())), '/') . '/offline';
}

/**
 * True when the offline folder is ALSO the folder of a store on this server (the active
 * one, or the previous one during a move) - storage moved from <P>/offline to <P>. Its
 * files are then real stored files, not copies: nothing may be copied there or removed.
 */
function filesOfflineOverlapsStore(PDO $conn, ?string $offlineRoot = null): bool
{
    $norm = function (string $p): string {
        $p = rtrim(str_replace('\\', '/', $p), '/');
        $r = @realpath($p);
        return $r !== false ? rtrim(str_replace('\\', '/', $r), '/') : $p;
    };
    $off = $norm($offlineRoot ?? filesOfflineRoot($conn));
    try {
        $cfgs = [filesStorageConfig($conn), filesPreviousStorageConfig($conn)];
    } catch (Throwable $e) {
        return true;   // cannot tell: treat as overlapping, so nothing is removed
    }
    foreach ($cfgs as $cfg) {
        if ($cfg && ($cfg['driver'] ?? 'local') === 'local' && isset($cfg['root']) && $norm((string)$cfg['root']) === $off) return true;
    }
    return false;
}

/**
 * The full path of a key's offline copy; null for anything that is not a key we write.
 *
 * @param string $key  files_versions.storage_path
 */
function filesOfflinePath(PDO $conn, string $key): ?string
{
    return filesStorageKeyIsValid($key) ? filesOfflineRoot($conn) . '/' . $key : null;
}

/**
 * True when at least one offline copy - or a temporary one - is on the server, so the
 * job still has something to tidy after the last mark is removed. Stops at the first
 * one found. Creates nothing: it is part of the job's health check, which runs on
 * installs that never used offline copies.
 */
function filesOfflineHasAnyCopy(PDO $conn): bool
{
    $root = filesOfflineRoot($conn);
    if (!is_dir($root)) return false;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        $rel = substr(str_replace('\\', '/', $f->getPathname()), strlen($root) + 1);
        if (filesStorageKeyIsValid($rel) || filesOfflineIsTmp($rel)) return true;
    }
    return false;
}

/**
 * True for a temporary copy's name: <key>.<12 hex>.tmp (FilesOfflineService::tmpFor), or
 * <key>.part - a copy the job is part-way through (FilesOfflineService::partFor).
 */
function filesOfflineIsTmp(string $rel): bool
{
    return (bool)preg_match('#^(\d{4}/\d{2}/\d{2}/[0-9a-f]{32}\.bin)\.(?:[0-9a-f]{12}\.tmp|part)$#', $rel);
}

/** True when a complete copy of the key is on the server (the size must match). */
function filesOfflineHasCopy(PDO $conn, string $key, int $size): bool
{
    $p = filesOfflinePath($conn, $key);
    if ($p === null) return false;
    clearstatcache(true, $p);
    return is_file($p) && filesize($p) === $size;
}

/**
 * True when offline copies mean anything: the files are (or, during a move, are still
 * partly) in a store that is not a folder on this server. Unknown counts as true, so
 * a broken setting never gets copies deleted.
 */
function filesOfflineApplies(PDO $conn): bool
{
    try {
        if (!(filesActiveStore($conn) instanceof LocalDriver)) return true;
        $prev = filesPreviousStore($conn);
        return $prev !== null && !($prev instanceof LocalDriver);
    } catch (Throwable $e) {
        return true;
    }
}

/** The administrator's limit on what offline copies may use, in bytes; null = no limit. */
function filesOfflineLimit(PDO $conn): ?int
{
    $v = (int)filesSetting($conn, 'files_offline_max_bytes', '0');
    return $v > 0 ? $v : null;
}

/**
 * What the copies use: ['files' => n, 'bytes' => n] from files_offline_copies. null
 * before Database Verification. Any other database error is thrown.
 */
function filesOfflineUsage(PDO $conn): ?array
{
    try {
        $r = $conn->query("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM files_offline_copies WHERE state = 'ready'")->fetch(PDO::FETCH_NUM);
    } catch (PDOException $e) {
        if (filesOfflineMissingTable($e)) return null;
        throw $e;
    }
    return ['files' => (int)$r[0], 'bytes' => (int)$r[1]];
}
