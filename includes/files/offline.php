<?php
/**
 * Files - offline copies ("Make available offline").
 *
 * When Files is stored in S3-compatible storage, a file or folder can be marked so
 * that a copy of its bytes is kept on the server too, at
 * <storage root>/offline/<key>. Reads use that copy first (filesServeBytes), so the
 * file opens fast and still opens while S3 cannot be reached. S3 stays the master.
 *
 * Marks live in files_offline (target_type folder|item). What is COVERED:
 * the current version of every live file that is marked itself or sits, at any
 * depth, under a marked live folder - so files uploaded later and new subfolders
 * are covered too. A mark with excluded = 1 ("Don't keep offline") leaves a file or
 * a folder out of a folder kept offline: THE NEAREST MARK WINS, as permissions
 * inherit - a folder marked inside an excluded one is kept again. Things in the
 * recycle bin are not covered (their marks stay and apply again after a restore).
 * Older versions are not kept offline.
 *
 * Copies share keys exactly as files_versions rows do (a copied file shares its
 * source's stored bytes), so "is this copy still needed" is always a question about
 * the KEY, answered by filesOfflineCoveredKeys(). Keys are never rewritten (a new
 * version gets a new key), so any copy with the right size holds the right bytes.
 *
 * Writes (marking, filling, removing) are in includes/services/files_offline.php.
 */

require_once __DIR__ . '/storage.php';
require_once __DIR__ . '/acl.php';

/**
 * Every mark: ['folder' => [id => true], 'item' => [id => true], 'exclude' =>
 * ['folder' => [id => true], 'item' => [id => true]]] - 'folder' and 'item' keep things
 * offline, 'exclude' leaves them out of a folder kept offline.
 * null when files_offline does not exist yet (before Database Verification) - nothing
 * can have been marked then. Any other database error is thrown.
 */
function filesOfflineMarks(PDO $conn): ?array
{
    try {
        try {
            $rows = $conn->query("SELECT target_type, target_id, excluded FROM files_offline")->fetchAll(PDO::FETCH_NUM);
        } catch (PDOException $e) {
            // The excluded column comes with a later Database Verification: no exclusions yet.
            if (($e->errorInfo[1] ?? null) !== 1054) throw $e;
            $rows = $conn->query("SELECT target_type, target_id, 0 FROM files_offline")->fetchAll(PDO::FETCH_NUM);
        }
    } catch (PDOException $e) {
        if (filesOfflineMissingTable($e)) return null;
        throw $e;
    }
    $out = ['folder' => [], 'item' => [], 'exclude' => ['folder' => [], 'item' => []]];
    foreach ($rows as [$type, $id, $ex]) {
        if (!isset($out[$type])) continue;
        if ((int)$ex === 1) $out['exclude'][$type][(int)$id] = true;
        else $out[$type][(int)$id] = true;
    }
    return $out;
}

/** True for a coverage state that keeps something offline ('self' or 'folder'). */
function filesOfflineKept(?string $state): bool
{
    return $state === 'self' || $state === 'folder';
}

/** True when a PDOException means files_offline does not exist. */
function filesOfflineMissingTable(PDOException $e): bool
{
    return ($e->errorInfo[1] ?? null) === 1146 || $e->getCode() === '42S02';
}

/**
 * Live folders with an offline state: [folderId => 'self' (marked) | 'folder' (a marked
 * folder above it) | 'excluded' (left out itself)]. Only 'self' and 'folder' are kept
 * offline (filesOfflineKept); a folder under an excluded one has no state - the nearest
 * mark wins.
 *
 * @param ?array $marks  from filesOfflineMarks()
 */
function filesOfflineCoveredFolders(PDO $conn, ?array $marks): array
{
    if (!$marks || (!$marks['folder'] && !($marks['exclude']['folder'] ?? []))) return [];
    $tree = FilesAcl::tree($conn);
    $memo = [];
    $state = function (int $id) use (&$state, &$memo, $tree, $marks): ?string {
        if (array_key_exists($id, $memo)) return $memo[$id];
        $memo[$id] = null;   // cycle guard
        if (!isset($tree[$id])) return null;
        if (isset($marks['folder'][$id])) return $memo[$id] = 'self';
        $p = $tree[$id]['parent_id'];
        $above = $p !== null && filesOfflineKept($state($p));
        // Left out only while a folder above keeps it; an exclusion nothing covers means nothing.
        if (isset($marks['exclude']['folder'][$id])) return $memo[$id] = $above ? 'excluded' : null;
        return $memo[$id] = $above ? 'folder' : null;
    };
    $out = [];
    foreach ($tree as $id => $f) {
        $s = $state($id);
        if ($s !== null) $out[$id] = $s;
    }
    return $out;
}

/**
 * How one live file is covered: 'self' (marked), 'folder' (its folder is covered) or null.
 *
 * @param array  $coveredFolders  from filesOfflineCoveredFolders()
 * @param ?array $marks           from filesOfflineMarks()
 */
function filesOfflineItemCoverage(array $coveredFolders, ?array $marks, int $itemId, int $folderId): ?string
{
    if ($marks && isset($marks['item'][$itemId])) return 'self';
    $kept = filesOfflineKept($coveredFolders[$folderId] ?? null);
    if ($marks && isset($marks['exclude']['item'][$itemId])) return $kept ? 'excluded' : null;
    return $kept ? 'folder' : null;
}

/**
 * The stored files that should have an offline copy: [storage_path => ['size' => int,
 * 'sha256' => ?string]] - the current version of every live, covered file.
 *
 * @param ?array $marks  from filesOfflineMarks(); read when omitted
 */
function filesOfflineCoveredKeys(PDO $conn, ?array $marks = null): array
{
    $marks ??= filesOfflineMarks($conn);
    if (!$marks || (!$marks['folder'] && !$marks['item'])) return [];
    $tree    = FilesAcl::tree($conn);
    $folders = array_keys(array_filter(filesOfflineCoveredFolders($conn, $marks), 'filesOfflineKept'));
    $items   = array_keys($marks['item']);

    // Ids are written in as integers rather than placeholders: a big tree can cover more
    // folders than a prepared statement allows placeholders (65,535).
    $where = [];
    if ($folders) $where[] = 'i.folder_id IN (' . implode(',', array_map('intval', $folders)) . ')';
    if ($items)   $where[] = 'i.id IN (' . implode(',', array_map('intval', $items)) . ')';
    // Every marked folder is in the recycle bin and no file is marked: nothing is covered.
    if (!$where) return [];
    $st = $conn->query("SELECT i.id, i.folder_id, v.storage_path, v.size_bytes, v.sha256
                          FROM files_items i
                          JOIN files_versions v ON v.id = i.current_version_id
                         WHERE i.deleted_datetime IS NULL AND (" . implode(' OR ', $where) . ")");
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if (!isset($tree[(int)$r['folder_id']])) continue;   // its folder is in the recycle bin
        $id = (int)$r['id'];
        if (isset($marks['exclude']['item'][$id]) && !isset($marks['item'][$id])) continue;   // left out of its folder
        $key = (string)$r['storage_path'];
        if (!filesStorageKeyIsValid($key)) continue;
        $out[$key] = ['size' => (int)$r['size_bytes'], 'sha256' => $r['sha256'] !== null ? (string)$r['sha256'] : null];
    }
    return $out;
}

/**
 * The marks to SHOW (badges, Properties): the marks while offline copies mean something,
 * null when they do not (Files stored in a server folder - marks are kept but have no
 * effect, and the menu to remove them is hidden, so a badge would only mislead).
 */
function filesOfflineDisplayMarks(PDO $conn): ?array
{
    return filesOfflineApplies($conn) ? filesOfflineMarks($conn) : null;
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
function filesOfflineOverlapsStore(PDO $conn): bool
{
    $norm = function (string $p): string {
        $p = rtrim(str_replace('\\', '/', $p), '/');
        $r = @realpath($p);
        return $r !== false ? rtrim(str_replace('\\', '/', $r), '/') : $p;
    };
    $off = $norm(filesOfflineRoot($conn));
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
 * True when at least one offline copy - or a temporary one a failed upload left - is on
 * the server, so the job still has something to tidy after the last mark is removed.
 * Stops at the first one found. Creates nothing: it is part of the job's health check,
 * which runs on installs that never used offline copies.
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

/** True for a temporary copy's name: <key>.<12 hex>.tmp (FilesOfflineService::tmpFor). */
function filesOfflineIsTmp(string $rel): bool
{
    return (bool)preg_match('#^(\d{4}/\d{2}/\d{2}/[0-9a-f]{32}\.bin)\.[0-9a-f]{12}\.tmp$#', $rel);
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
