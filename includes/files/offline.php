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
 * are covered too. Things in the recycle bin are not covered (their marks stay and
 * apply again after a restore). Older versions are not kept offline.
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
 * Every mark: ['folder' => [id => true], 'item' => [id => true]].
 * null when files_offline does not exist yet (before Database Verification) - nothing
 * can have been marked then. Any other database error is thrown.
 */
function filesOfflineMarks(PDO $conn): ?array
{
    try {
        $rows = $conn->query("SELECT target_type, target_id FROM files_offline")->fetchAll(PDO::FETCH_NUM);
    } catch (PDOException $e) {
        if (filesOfflineMissingTable($e)) return null;
        throw $e;
    }
    $out = ['folder' => [], 'item' => []];
    foreach ($rows as [$type, $id]) {
        if (isset($out[$type])) $out[$type][(int)$id] = true;
    }
    return $out;
}

/** True when a PDOException means files_offline does not exist. */
function filesOfflineMissingTable(PDOException $e): bool
{
    return ($e->errorInfo[1] ?? null) === 1146 || $e->getCode() === '42S02';
}

/**
 * Live folders that are covered: [folderId => 'self' (marked) | 'folder' (a marked
 * folder above it)].
 *
 * @param ?array $marks  from filesOfflineMarks()
 */
function filesOfflineCoveredFolders(PDO $conn, ?array $marks): array
{
    if (!$marks || !$marks['folder']) return [];
    $tree = FilesAcl::tree($conn);
    $memo = [];
    $state = function (int $id) use (&$state, &$memo, $tree, $marks): ?string {
        if (array_key_exists($id, $memo)) return $memo[$id];
        $memo[$id] = null;   // cycle guard
        if (!isset($tree[$id])) return null;
        if (isset($marks['folder'][$id])) return $memo[$id] = 'self';
        $p = $tree[$id]['parent_id'];
        return $memo[$id] = ($p !== null && $state($p) !== null) ? 'folder' : null;
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
    return isset($coveredFolders[$folderId]) ? 'folder' : null;
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
    $folders = array_keys(filesOfflineCoveredFolders($conn, $marks));
    $items   = array_keys($marks['item']);

    // Ids are written in as integers rather than placeholders: a big tree can cover more
    // folders than a prepared statement allows placeholders (65,535).
    $where = [];
    if ($folders) $where[] = 'i.folder_id IN (' . implode(',', array_map('intval', $folders)) . ')';
    if ($items)   $where[] = 'i.id IN (' . implode(',', array_map('intval', $items)) . ')';
    // Every marked folder is in the recycle bin and no file is marked: nothing is covered.
    if (!$where) return [];
    $st = $conn->query("SELECT i.folder_id, v.storage_path, v.size_bytes, v.sha256
                          FROM files_items i
                          JOIN files_versions v ON v.id = i.current_version_id
                         WHERE i.deleted_datetime IS NULL AND (" . implode(' OR ', $where) . ")");
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if (!isset($tree[(int)$r['folder_id']])) continue;   // its folder is in the recycle bin
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

/** Where offline copies live: <storage root>/offline. Not created here. */
function filesOfflineRoot(PDO $conn): string
{
    return filesStorageRoot($conn) . '/offline';
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
 * True when at least one offline copy is on the server - so the job still has
 * something to tidy after the last mark is removed. Stops at the first one found.
 */
function filesOfflineHasAnyCopy(PDO $conn): bool
{
    $root = filesOfflineRoot($conn);
    if (!is_dir($root)) return false;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        $rel = substr(str_replace('\\', '/', $f->getPathname()), strlen($root) + 1);
        if (filesStorageKeyIsValid($rel)) return true;
    }
    return false;
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
