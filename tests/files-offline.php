<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * Files offline copies ("Make available offline", includes/files/offline.php and
 * includes/services/files_offline.php).
 *
 * What this guards, each of which would serve the wrong bytes, waste or lose a copy:
 *   - a folder mark not covering subfolders, or covering things in the recycle bin
 *   - an old version kept instead of the current one
 *   - a partial or corrupted copy being served
 *   - a copy shared by two files being deleted while the other still needs it
 *   - copies outliving their files (purge, recycle bin, storage moved back to a folder)
 *   - anyone who cannot see a folder marking it
 *
 * Folders, files and grants are ZZ fixtures; the analysts are ids nobody has. Stored
 * files go to temporary folders; "S3" is a stand-in driver that can be switched off.
 * Everything runs inside ONE transaction that is rolled back, settings included.
 *
 * Run: FREEITSM_TEST_DATABASE=<db> php tests/files-offline.php
 */

$root = dirname(__DIR__);
require_once "$root/config.php";
require_once "$root/includes/functions.php";
require_once "$root/includes/encryption.php";
require_once "$root/includes/files/storage.php";
require_once "$root/includes/files/offline.php";
require_once "$root/includes/files/names.php";
require_once "$root/includes/services/files_offline.php";
require_once "$root/includes/services/files_recycle.php";

$pass = 0; $fail = 0;
function ok(string $label, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; printf("  PASS %-70s\n", $label); }
    else       { $fail++; printf("  FAIL %-70s %s\n", $label, $detail); }
}
function setSetting(PDO $conn, string $k, ?string $v): void {
    $conn->prepare("DELETE FROM system_settings WHERE setting_key = ?")->execute([$k]);
    if ($v !== null) $conn->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)")->execute([$k, $v]);
    filesStorageReset();
}
function folder(PDO $conn, ?int $parent, string $name): int {
    $conn->prepare("INSERT INTO files_folders (parent_id, name) VALUES (?, ?)")->execute([$parent, $name]);
    FilesAcl::reset();
    return (int)$conn->lastInsertId();
}
function grant(PDO $conn, int $folder, int $analyst, int $level): void {
    $conn->prepare("INSERT INTO files_permissions (folder_id, principal_type, principal_id, level) VALUES (?, 'analyst', ?, ?)")->execute([$folder, $analyst, $level]);
    FilesAcl::reset();
}
/** Writes bytes under a fresh key in $dir and returns the key. */
function stored(string $dir, string $bytes): string {
    $key = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    @mkdir(dirname("$dir/$key"), 0777, true);
    file_put_contents("$dir/$key", $bytes);
    return $key;
}
/** A file with one version; $key reuses a stored file (a copy), else a new one is written. */
function item(PDO $conn, string $dir, int $folder, string $name, ?string $key = null): array {
    $bytes = $key === null ? "bytes of $name" : file_get_contents("$dir/$key");   // a copy shares its source's bytes
    if ($key === null) $key = stored($dir, $bytes);
    $size = strlen($bytes);
    $conn->prepare("INSERT INTO files_items (folder_id, name, size_bytes) VALUES (?, ?, ?)")->execute([$folder, $name, $size]);
    $id = (int)$conn->lastInsertId();
    $conn->prepare("INSERT INTO files_versions (item_id, version_no, storage_path, size_bytes, sha256) VALUES (?, 1, ?, ?, ?)")
         ->execute([$id, $key, $size, hash('sha256', $bytes)]);
    $vid = (int)$conn->lastInsertId();
    $conn->prepare("UPDATE files_items SET current_version_id = ? WHERE id = ?")->execute([$vid, $id]);
    return ['id' => $id, 'key' => $key, 'size' => $size, 'bytes' => $bytes];
}
/** Adds version 2 of an item and makes it current; returns its key. */
function newVersion(PDO $conn, string $dir, array $it): array {
    $bytes = "version two of {$it['id']}";
    $key = stored($dir, $bytes);
    $conn->prepare("INSERT INTO files_versions (item_id, version_no, storage_path, size_bytes, sha256) VALUES (?, 2, ?, ?, ?)")
         ->execute([$it['id'], $key, strlen($bytes), hash('sha256', $bytes)]);
    $vid = (int)$conn->lastInsertId();
    $conn->prepare("UPDATE files_items SET current_version_id = ?, size_bytes = ? WHERE id = ?")->execute([$vid, strlen($bytes), $it['id']]);
    return ['id' => $it['id'], 'key' => $key, 'size' => strlen($bytes), 'bytes' => $bytes];
}
function softDelete(PDO $conn, string $type, int $id, ?string $when = 'UTC_TIMESTAMP()'): void {
    $t = $type === 'folder' ? 'files_folders' : 'files_items';
    $conn->prepare("UPDATE $t SET deleted_by = NULL, deleted_datetime = " . ($when ?? 'NULL') . " WHERE id = ?")->execute([$id]);
    FilesAcl::reset();
}
function mark(PDO $conn, string $type, int $id): void {
    $conn->prepare("INSERT INTO files_offline (target_type, target_id) VALUES (?, ?)")->execute([$type, $id]);
}
function unmarkRow(PDO $conn, string $type, int $id): void {
    $conn->prepare("DELETE FROM files_offline WHERE target_type = ? AND target_id = ?")->execute([$type, $id]);
}

/** Stand-in for S3: a folder that is NOT a LocalDriver, and can be switched off. */
final class ZzFakeS3 implements StorageDriver
{
    public bool $down = false;
    public int $reads = 0;
    private LocalDriver $d;
    public function __construct(string $dir) { $this->d = new LocalDriver($dir); }
    private function up(): void { if ($this->down) throw new StorageUnavailable('zz: S3 is switched off'); }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->up(); $this->d->putFile($key, $localPath, $move); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { $this->up(); $this->reads++; $this->d->readRange($key, $start, $end, $sink); }
    public function readTo(string $key, string $localPath): void { $this->up(); $this->reads++; $this->d->readTo($key, $localPath); }
    public function size(string $key): ?int { $this->up(); return $this->d->size($key); }
    public function delete(string $key): void { $this->up(); $this->d->delete($key); }
    public function label(): string { return 'zz fake S3'; }
}
/** Makes the stand-in the active store (as if Files -> Settings -> Storage said S3). */
function useFake(?ZzFakeS3 $fake): void {
    filesStorageReset();
    if ($fake) FilesStorageCache::$drivers['active'] = $fake;
}
/** Serves a whole version through filesServeBytes(); returns [status, bytes sent]. */
function serve(PDO $conn, array $it): array {
    ob_start();
    $status = filesServeBytes($conn, ['storage_path' => $it['key'], 'size_bytes' => $it['size']], 0, $it['size'] - 1, function () {});
    return [$status, (string)ob_get_clean()];
}
/** Puts a copy of $it in the offline folder (optionally with other bytes). */
function putCopy(PDO $conn, array $it, ?string $bytes = null): string {
    $p = filesOfflinePath($conn, $it['key']);
    @mkdir(dirname($p), 0777, true);
    file_put_contents($p, $bytes ?? $it['bytes']);
    return $p;
}

$conn = connectToDatabase();
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$dbName = (string)$conn->query('SELECT DATABASE()')->fetchColumn();
if (getenv('FREEITSM_TEST_DATABASE') !== $dbName) {
    echo "SKIPPED: set FREEITSM_TEST_DATABASE to the database this may write to (this one is $dbName).\n";
    exit(0);
}

echo "\nFiles offline copies\n" . str_repeat('=', 72) . "\n";
$store = sys_get_temp_dir() . '/zz-off-' . bin2hex(random_bytes(4));   // the local storage folder
$s3dir = sys_get_temp_dir() . '/zz-off-s3-' . bin2hex(random_bytes(4)); // what the stand-in "S3" holds
mkdir($store); mkdir($s3dir);

$conn->beginTransaction();
try {
    foreach (['files_storage_driver', 'files_storage_previous', 'files_storage_cleanup'] as $k) setSetting($conn, $k, null);
    setSetting($conn, 'files_storage_root', $store);
    $conn->exec("DELETE FROM files_offline");

    // ── Coverage ───────────────────────────────────────────────────────
    $A = folder($conn, null, 'ZZ Off A');
    $B = folder($conn, $A, 'ZZ Off B');
    $C = folder($conn, $B, 'ZZ Off C');
    $X = folder($conn, null, 'ZZ Off X');
    $a1 = item($conn, $s3dir, $A, 'zz-a1.txt');
    $b1 = item($conn, $s3dir, $B, 'zz-b1.txt');
    $c1 = item($conn, $s3dir, $C, 'zz-c1.txt');
    $x1 = item($conn, $s3dir, $X, 'zz-x1.txt');
    $x2 = item($conn, $s3dir, $X, 'zz-x2.txt', $a1['key']);   // a copy: shares a1's stored file

    ok('CONTROL: no marks, nothing covered', filesOfflineCoveredKeys($conn) === []);

    mark($conn, 'folder', $B);
    $marks = filesOfflineMarks($conn);
    $cf = filesOfflineCoveredFolders($conn, $marks);
    ok('a marked folder is covered as itself, its subfolder from the folder', ($cf[$B] ?? null) === 'self' && ($cf[$C] ?? null) === 'folder', json_encode($cf));
    ok('...and the folder above it is not', !isset($cf[$A]));
    $keys = filesOfflineCoveredKeys($conn);
    ok('covered keys: the files in the folder and below it', isset($keys[$b1['key']], $keys[$c1['key']]) && count($keys) === 2, json_encode(array_keys($keys)));
    ok('a covered key carries its size and SHA-256', $keys[$b1['key']]['size'] === $b1['size'] && $keys[$b1['key']]['sha256'] === hash('sha256', $b1['bytes']));

    mark($conn, 'item', $x1['id']);
    $marks = filesOfflineMarks($conn);
    $cf = filesOfflineCoveredFolders($conn, $marks);
    ok('a marked file is covered as itself', filesOfflineItemCoverage($cf, $marks, $x1['id'], $X) === 'self');
    ok('a file in a covered folder is covered from the folder', filesOfflineItemCoverage($cf, $marks, $c1['id'], $C) === 'folder');
    ok('its unmarked neighbour is not', filesOfflineItemCoverage($cf, $marks, $x2['id'], $X) === null);

    softDelete($conn, 'folder', $C);
    ok('a folder in the recycle bin is not covered', !isset(filesOfflineCoveredKeys($conn)[$c1['key']]));
    softDelete($conn, 'folder', $C, null);
    ok('...and is again once restored', isset(filesOfflineCoveredKeys($conn)[$c1['key']]));
    softDelete($conn, 'item', $b1['id']);
    ok('a file in the recycle bin is not covered', !isset(filesOfflineCoveredKeys($conn)[$b1['key']]));
    softDelete($conn, 'item', $b1['id'], null);

    $b1v2 = newVersion($conn, $s3dir, $b1);
    $keys = filesOfflineCoveredKeys($conn);
    ok('a new version: the current one is covered, the old one is not', isset($keys[$b1v2['key']]) && !isset($keys[$b1['key']]));

    mark($conn, 'folder', $A);
    ok('a stored file shared by two files is covered once', isset(filesOfflineCoveredKeys($conn)[$a1['key']]));

    ok('a path that is not a key gets no offline path', filesOfflinePath($conn, '../etc/passwd') === null);
    ok('a key maps under <storage folder>/offline/', filesOfflinePath($conn, $a1['key']) === "$store/offline/{$a1['key']}", (string)filesOfflinePath($conn, $a1['key']));
    ok('no copy yet', !filesOfflineHasCopy($conn, $a1['key'], $a1['size']));
    ok('a local folder backend: offline copies do not apply', filesOfflineApplies($conn) === false);

    // ── Reads ──────────────────────────────────────────────────────────
    $fake = new ZzFakeS3($s3dir);
    useFake($fake);
    ok('a store that is not a folder: offline copies apply', filesOfflineApplies($conn) === true);
    $cp = putCopy($conn, $x1);
    $fake->down = true;
    [$st, $out] = serve($conn, $x1);
    ok('the copy is served while S3 is down', $st === 0 && $out === $x1['bytes'], "status $st, '$out'");
    $fake->down = false; $fake->reads = 0;
    [$st, $out] = serve($conn, $x1);
    ok('...and preferred while S3 is up (S3 not asked)', $st === 0 && $out === $x1['bytes'] && $fake->reads === 0, "reads {$fake->reads}");
    file_put_contents($cp, substr($x1['bytes'], 0, -1));
    $fake->down = true;
    [$st] = serve($conn, $x1);
    ok('a copy of the wrong size is never served', $st === 503, "status $st");
    [$st] = serve($conn, $c1);
    ok('no copy and S3 down: unavailable (503)', $st === 503, "status $st");
    $fake->down = false;
    useFake(null);
    // Local folder backend: the real file is served even if an "offline" file differs.
    $loc = item($conn, $store, $X, 'zz-local.txt');
    putCopy($conn, $loc, str_repeat('Z', $loc['size']));
    [$st, $out] = serve($conn, $loc);
    ok('a folder backend never reads offline copies', $st === 0 && $out === $loc['bytes'], "'$out'");

    // ── The service: marking and removing ─────────────────────────────
    $conn->exec("DELETE FROM files_offline");
    @unlink(filesOfflinePath($conn, $loc['key']));
    @unlink(filesOfflinePath($conn, $x1['key']));
    $V = 990000101;   // View on ZZ Off A and ZZ Off X
    $N = 990000102;   // nothing
    grant($conn, $A, $V, FilesAcl::VIEW);
    grant($conn, $X, $V, FilesAcl::VIEW);

    try { FilesOfflineService::mark($conn, $V, 'item', $x1['id']); ok('a folder backend refuses marking', false); }
    catch (InvalidArgumentException $e) { ok('a folder backend refuses marking', str_contains($e->getMessage(), 'S3'), $e->getMessage()); }

    useFake($fake);
    try { FilesOfflineService::mark($conn, $N, 'folder', $A); ok('no access: marking is refused as not found', false); }
    catch (InvalidArgumentException $e) { ok('no access: marking is refused as not found', $e->getMessage() === 'Folder not found.', $e->getMessage()); }
    $r = FilesOfflineService::mark($conn, $V, 'item', $x1['id']);
    ok('View is enough to mark a file, and it is copied at once', $r['ready'] === true && filesOfflineHasCopy($conn, $x1['key'], $x1['size']), json_encode($r));
    ok('...with the right bytes', file_get_contents(filesOfflinePath($conn, $x1['key'])) === $x1['bytes']);
    $s = $conn->prepare("SELECT COUNT(*) FROM files_audit WHERE action = 'offline' AND item_id = ? AND analyst_id = ?");
    $s->execute([$x1['id'], $V]);
    ok('marking is in the audit trail', (int)$s->fetchColumn() === 1);
    $r = FilesOfflineService::mark($conn, $V, 'item', $x1['id']);
    ok('marking twice is harmless', $r['ready'] === true && (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn() === 1);

    $r = FilesOfflineService::mark($conn, $V, 'folder', $A);
    ok('marking a folder leaves the copying to the job', $r['ready'] === false);
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('the job copies everything the folder covers', filesOfflineHasCopy($conn, $a1['key'], $a1['size']) && filesOfflineHasCopy($conn, $b1v2['key'], $b1v2['size'])
        && filesOfflineHasCopy($conn, $c1['key'], $c1['size']) && $y['copied'] === 3 && $y['failed'] === 0 && $y['done'], json_encode($y));
    ok('...but not an old version', !is_file(filesOfflinePath($conn, $b1['key'])));

    // Corrupted on the way: the SHA-256 does not match, so it is not kept.
    $conn->prepare("UPDATE files_versions SET sha256 = ? WHERE storage_path = ?")->execute([str_repeat('0', 64), $c1['key']]);
    unlink(filesOfflinePath($conn, $c1['key']));
    $y = FilesOfflineService::sync($conn, time() + 60);
    $tmps = glob(dirname(filesOfflinePath($conn, $c1['key'])) . '/*.tmp') ?: [];
    ok('a copy that does not match its SHA-256 is not kept', $y['failed'] === 1 && !is_file(filesOfflinePath($conn, $c1['key'])) && !$tmps, json_encode($y));
    $conn->prepare("UPDATE files_versions SET sha256 = ? WHERE storage_path = ?")->execute([hash('sha256', $c1['bytes']), $c1['key']]);

    $fake->down = true;
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('S3 down: the job stops filling, without an exception', !$y['done'] && $y['copied'] === 0, json_encode($y));
    $fake->down = false;
    FilesOfflineService::sync($conn, time() + 60);

    // x2 shares a1's stored file. Mark x2, then remove A's mark: the copy must stay.
    FilesOfflineService::mark($conn, $V, 'item', $x2['id']);
    $r = FilesOfflineService::unmark($conn, $V, 'folder', $A);
    ok('removing a mark deletes copies nothing else covers', !is_file(filesOfflinePath($conn, $b1v2['key'])) && !is_file(filesOfflinePath($conn, $c1['key'])), json_encode($r));
    ok('...but keeps one another marked file shares', filesOfflineHasCopy($conn, $a1['key'], $a1['size']));
    FilesOfflineService::unmark($conn, $V, 'item', $x2['id']);
    ok('...until that one is removed too', !is_file(filesOfflinePath($conn, $a1['key'])));

    // Recycle bin and purge.
    FilesOfflineService::mark($conn, $V, 'folder', $X);
    FilesOfflineService::sync($conn, time() + 60);
    ok('CONTROL: a copy exists before the delete', filesOfflineHasCopy($conn, $x2['key'], $x2['size']));
    softDelete($conn, 'item', $x2['id']);
    FilesOfflineService::sync($conn, time() + 60);
    ok('the job removes the copy of a file in the recycle bin', !is_file(filesOfflinePath($conn, $x2['key'])));
    softDelete($conn, 'item', $x2['id'], null);
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and makes it again after a restore', filesOfflineHasCopy($conn, $x2['key'], $x2['size']));
    $gone = item($conn, $s3dir, $X, 'zz-gone.txt');
    FilesOfflineService::sync($conn, time() + 60);
    ok('CONTROL: the file to purge has a copy', filesOfflineHasCopy($conn, $gone['key'], $gone['size']));
    grant($conn, $X, 990000103, FilesAcl::MODIFY);
    softDelete($conn, 'item', $gone['id']);
    FilesRecycleService::purge($conn, 990000103, 'item', $gone['id']);
    ok('deleting permanently removes the copy at once', !is_file(filesOfflinePath($conn, $gone['key'])));

    $Z = folder($conn, null, 'ZZ Off Z');
    mark($conn, 'folder', $Z);
    $conn->prepare("DELETE FROM files_folders WHERE id = ?")->execute([$Z]);
    FilesAcl::reset();
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('marks on things that no longer exist are dropped', $y['marks_dropped'] === 1, json_encode($y));

    // Uploads into a covered folder keep a copy straight away.
    $part = "$store/zz-upload.part";
    file_put_contents($part, 'uploaded bytes');
    $newKey = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    FilesOfflineService::keepUploadCopy($conn, $X, null, $part, $newKey);
    ok('an upload into a covered folder is copied at once', is_file(filesOfflinePath($conn, $newKey)) && file_get_contents(filesOfflinePath($conn, $newKey)) === 'uploaded bytes');
    $otherKey = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    FilesOfflineService::keepUploadCopy($conn, $B, null, $part, $otherKey);
    ok('...and one into an uncovered folder is not', !is_file(filesOfflinePath($conn, $otherKey)));
    ok('the part file is left for the upload to store', is_file($part));

    $u = FilesOfflineService::usage($conn);
    ok('usage counts the copies on the server', $u !== null && $u['files'] >= 2 && $u['bytes'] > 0, json_encode($u));

    // Storage moved back to a folder: copies mean nothing any more.
    useFake(null);
    FilesOfflineService::keepUploadCopy($conn, $X, null, $part, $otherKey);
    ok('CONTROL: a folder backend keeps no upload copy', !is_file(filesOfflinePath($conn, $otherKey)));
    $y = FilesOfflineService::sync($conn, time() + 60);
    $left = 0;
    if (is_dir(filesOfflineRoot($conn))) foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(filesOfflineRoot($conn), FilesystemIterator::SKIP_DOTS)) as $f) $left++;
    ok('no S3 in use: the job removes every copy', $left === 0 && $y['removed'] >= 2, json_encode($y) . " left $left");
    $conn->exec("DELETE FROM files_offline");
} catch (Throwable $e) {
    ok('no unexpected exception', false, get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
} finally {
    if ($conn->inTransaction()) $conn->rollBack();
    filesStorageReset();
    foreach ([$store, $s3dir] as $d) {
        if (!is_dir($d)) continue;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        @rmdir($d);
    }
}

echo str_repeat('-', 72) . "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
