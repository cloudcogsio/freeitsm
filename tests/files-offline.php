<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * Files offline copies ("Make available offline", includes/files/offline.php and
 * includes/services/files_offline.php).
 *
 * What this guards, each of which would serve the wrong bytes, waste or lose a copy,
 * or do what a person could not do by hand:
 *   - a folder mark not covering subfolders, or covering things in the recycle bin
 *   - a mark covering what the person who made it cannot open (a subfolder that stops
 *     inheriting, access taken away, a deactivated account) - or switching off what a
 *     mark above still keeps
 *   - a folder's tick telling a viewer about a subfolder they cannot see
 *   - someone with View only (or no analyst at all) changing what is kept offline
 *   - an old version kept instead of the current one
 *   - a partial or corrupted copy being served
 *   - a copy shared by two files being deleted while the other still needs it
 *   - copies outliving their files (purge, recycle bin, versions, storage moved)
 *   - a tick that says "available offline" before it is, or "being copied" for good
 *   - one huge copy holding the job past its time
 *   - copies going past the administrator's limit
 *   - memory growing with the number of files (every list load, removal and job run)
 *   - anything breaking before Database Verification (no tables yet)
 *
 * Folders, files, grants and analysts are ZZ fixtures. Stored files go to temporary
 * folders; "S3" is a stand-in driver that can be switched off. The main part runs
 * inside ONE transaction that is rolled back, settings included. Two parts run on their
 * own afterwards: one renames the offline tables for a while (and always puts them
 * back), one calls api/files/offline.php over HTTP (FREEITSM_TEST_URL).
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
require_once "$root/includes/services/files_versions.php";
require_once "$root/includes/job_registry.php";

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
function analyst(PDO $conn, string $name, int $active = 1, int $admin = 0): int {
    $u = $name . bin2hex(random_bytes(3));
    $conn->prepare("INSERT INTO analysts (username, email, full_name, password_hash, is_active, is_admin) VALUES (?, ?, ?, '!', ?, ?)")
         ->execute([$u, "$u@example.invalid", "ZZ $name", $active, $admin]);
    return (int)$conn->lastInsertId();
}
/** A folder; a top-level one is granted Modify to the analyst who marks things in this test. */
function folder(PDO $conn, ?int $parent, string $name, bool $inherit = true): int {
    $conn->prepare("INSERT INTO files_folders (parent_id, name, inherit_permissions) VALUES (?, ?, ?)")->execute([$parent, $name, $inherit ? 1 : 0]);
    $id = (int)$conn->lastInsertId();
    FilesAcl::reset();
    if ($parent === null) grant($conn, $id, $GLOBALS['V'], FilesAcl::MODIFY);
    return $id;
}
function grant(PDO $conn, int $folder, int $analyst, int $level): void {
    $conn->prepare("INSERT INTO files_permissions (folder_id, principal_type, principal_id, level) VALUES (?, 'analyst', ?, ?)
                    ON DUPLICATE KEY UPDATE level = VALUES(level)")->execute([$folder, $analyst, $level]);
    FilesAcl::reset();
}
function revoke(PDO $conn, int $folder, int $analyst): void {
    $conn->prepare("DELETE FROM files_permissions WHERE folder_id = ? AND principal_type = 'analyst' AND principal_id = ?")->execute([$folder, $analyst]);
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
    return ['id' => $id, 'key' => $key, 'size' => $size, 'bytes' => $bytes, 'folder' => $folder];
}
/** Adds version 2 of an item and makes it current; returns its key. */
function newVersion(PDO $conn, string $dir, array $it): array {
    $bytes = "version two of {$it['id']}";
    $key = stored($dir, $bytes);
    $conn->prepare("INSERT INTO files_versions (item_id, version_no, storage_path, size_bytes, sha256) VALUES (?, 2, ?, ?, ?)")
         ->execute([$it['id'], $key, strlen($bytes), hash('sha256', $bytes)]);
    $vid = (int)$conn->lastInsertId();
    $conn->prepare("UPDATE files_items SET current_version_id = ?, size_bytes = ? WHERE id = ?")->execute([$vid, strlen($bytes), $it['id']]);
    return ['id' => $it['id'], 'key' => $key, 'size' => strlen($bytes), 'bytes' => $bytes, 'folder' => $it['folder']];
}
function softDelete(PDO $conn, string $type, int $id, ?string $when = 'UTC_TIMESTAMP()'): void {
    $t = $type === 'folder' ? 'files_folders' : 'files_items';
    $conn->prepare("UPDATE $t SET deleted_by = NULL, deleted_datetime = " . ($when ?? 'NULL') . " WHERE id = ?")->execute([$id]);
    FilesAcl::reset();
}
/** A mark straight in the table, made by $by (the marking analyst of this test by default). */
function mark(PDO $conn, string $type, int $id, ?int $by = null): void {
    $conn->prepare("INSERT INTO files_offline (target_type, target_id, marked_by) VALUES (?, ?, ?)")->execute([$type, $id, $by ?? $GLOBALS['V']]);
}
/** The keys the marks cover now: [key => ['size', 'sha256']]. */
function coveredKeys(PDO $conn): array {
    $cov = FilesOfflineCoverage::load($conn);
    $cand = $cov->candidateSql();
    if ($cand === null) return [];
    $out = [];
    foreach ($conn->query("SELECT i.id, i.folder_id, v.storage_path, v.size_bytes, v.sha256 FROM files_items i
                             JOIN files_versions v ON v.id = i.current_version_id WHERE i.deleted_datetime IS NULL AND $cand")->fetchAll(PDO::FETCH_NUM) as [$id, $fid, $key, $size, $sha]) {
        if (filesOfflineKept($cov->item((int)$id, (int)$fid))) $out[$key] = ['size' => (int)$size, 'sha256' => $sha];
    }
    return $out;
}
function copyRow(PDO $conn, string $key): ?array {
    $st = $conn->prepare("SELECT state, size_bytes FROM files_offline_copies WHERE storage_path = ?");
    $st->execute([$key]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}
function itemState(PDO $conn, array $it): ?string {
    return filesOfflineItemStates($conn, [$it['id']])[$it['id']] ?? null;
}
function refused(callable $fn): string {
    try { $fn(); return '(not refused)'; }
    catch (InvalidArgumentException $e) { return $e->getMessage(); }
}
/** Removes a folder tree this test made. */
function rmTree(string $d): void {
    if (!is_dir($d)) return;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    @rmdir($d);
}

/** Stand-in for S3: a folder that is NOT a LocalDriver, and can be switched off. */
final class ZzFakeS3 implements StorageDriver
{
    public bool $down = false;
    public int $reads = 0;
    public int $delay = 0;   // seconds before a read starts (a slow store; waited out in steps, as sleep() can end early)
    private LocalDriver $d;
    public function __construct(string $dir) { $this->d = new LocalDriver($dir); }
    private function up(): void { if ($this->down) throw new StorageUnavailable('zz: S3 is switched off'); }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->up(); $this->d->putFile($key, $localPath, $move); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { $this->up(); $this->reads++; for ($until = microtime(true) + $this->delay; microtime(true) < $until; ) usleep(50000); $this->d->readRange($key, $start, $end, $sink); }
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

// A run stopped part-way through the "before Database Verification" part could have left
// the tables renamed: put them back first, and again however this run ends.
$hidden = ['files_offline' => 'zz_files_offline_hidden', 'files_offline_copies' => 'zz_files_offline_copies_hidden'];
$tablesBack = function () use ($conn, $hidden): void {
    if ($conn->inTransaction()) $conn->rollBack();
    foreach ($hidden as $real => $zz) {
        if ($conn->query("SHOW TABLES LIKE '$zz'")->fetchColumn() && !$conn->query("SHOW TABLES LIKE '$real'")->fetchColumn()) {
            $conn->exec("RENAME TABLE $zz TO $real");
        }
    }
};
$tablesBack();
register_shutdown_function($tablesBack);

echo "\nFiles offline copies\n" . str_repeat('=', 72) . "\n";
$store = sys_get_temp_dir() . '/zz-off-' . bin2hex(random_bytes(4));   // the local storage folder
$s3dir = sys_get_temp_dir() . '/zz-off-s3-' . bin2hex(random_bytes(4)); // what the stand-in "S3" holds
mkdir($store); mkdir($s3dir);
$extraDirs = [];   // other folders a check makes, removed at the end

$conn->beginTransaction();
try {
    foreach (['files_storage_driver', 'files_storage_previous', 'files_storage_cleanup', 'files_offline_max_bytes',
              'files_offline_limit_reached', 'files_offline_old_roots'] as $k) setSetting($conn, $k, null);
    setSetting($conn, 'files_storage_root', $store);
    $conn->exec("DELETE FROM files_offline");
    $conn->exec("DELETE FROM files_offline_copies");

    $V   = analyst($conn, 'zzoffv');            // marks things: Modify on every top-level ZZ folder
    $U   = analyst($conn, 'zzoffu');            // View only, where granted
    $N   = analyst($conn, 'zzoffn');            // nothing
    $D   = analyst($conn, 'zzoffd', 0);         // deactivated
    $ADM = analyst($conn, 'zzoffadm', 1, 1);    // an administrator: holds the Files storage permission

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

    ok('CONTROL: no marks, nothing covered', coveredKeys($conn) === []);
    mark($conn, 'folder', $B);
    $cov = FilesOfflineCoverage::load($conn);
    ok('a marked folder is covered as itself, its subfolder from the folder', $cov->folder($B) === 'self' && $cov->folder($C) === 'folder');
    ok('...and the folder above it is not', $cov->folder($A) === null);
    $keys = coveredKeys($conn);
    ok('covered: the files in the folder and below it', isset($keys[$b1['key']], $keys[$c1['key']]) && count($keys) === 2, json_encode(array_keys($keys)));
    mark($conn, 'item', $x1['id']);
    $cov = FilesOfflineCoverage::load($conn);
    ok('a marked file is covered as itself', $cov->item($x1['id'], $X) === 'self');
    ok('a file in a covered folder is covered from the folder', $cov->item($c1['id'], $C) === 'folder');
    ok('its unmarked neighbour is not', $cov->item($x2['id'], $X) === null);
    softDelete($conn, 'folder', $C);
    ok('a folder in the recycle bin is not covered', !isset(coveredKeys($conn)[$c1['key']]));
    softDelete($conn, 'folder', $C, null);
    ok('...and is again once restored', isset(coveredKeys($conn)[$c1['key']]));
    softDelete($conn, 'item', $b1['id']);
    ok('a file in the recycle bin is not covered', !isset(coveredKeys($conn)[$b1['key']]));
    softDelete($conn, 'item', $b1['id'], null);
    $b1v2 = newVersion($conn, $s3dir, $b1);
    $keys = coveredKeys($conn);
    ok('a new version: the current one is covered, the old one is not', isset($keys[$b1v2['key']]) && !isset($keys[$b1['key']]));
    ok('a path that is not a key gets no offline path', filesOfflinePath($conn, '../etc/passwd') === null);
    ok('a key maps under <storage folder>/offline/', filesOfflinePath($conn, $a1['key']) === "$store/offline/{$a1['key']}");
    ok('a local folder backend: offline copies do not apply', filesOfflineApplies($conn) === false);

    // ── A mark covers only what the person who made it can open ────────
    $H = folder($conn, $A, 'ZZ Off H (closed)', false);   // stops inheriting: V cannot see it
    $h1 = item($conn, $s3dir, $H, 'zz-h1.txt');
    $conn->exec("DELETE FROM files_offline");
    mark($conn, 'folder', $A);
    $cov = FilesOfflineCoverage::load($conn);
    ok('a subfolder closed to the person who marked the folder is not covered', $cov->folder($H) === null && !isset(coveredKeys($conn)[$h1['key']]));
    ok('...while what they can see is', $cov->folder($B) === 'folder' && isset(coveredKeys($conn)[$a1['key']]));
    grant($conn, $H, $V, FilesAcl::VIEW);
    ok('given access to it, their mark covers it', isset(coveredKeys($conn)[$h1['key']]));
    revoke($conn, $H, $V);
    ok('access taken away: it is no longer covered', !isset(coveredKeys($conn)[$h1['key']]));
    $conn->exec("DELETE FROM files_offline");
    mark($conn, 'folder', $A, $D);
    grant($conn, $A, $D, FilesAcl::MODIFY);
    ok('a mark made by a deactivated analyst covers nothing', coveredKeys($conn) === []);
    $conn->exec("DELETE FROM files_offline");
    mark($conn, 'folder', $A, 0);
    ok('...nor one with nobody recorded', coveredKeys($conn) === []);
    $conn->exec("DELETE FROM files_offline");

    // A mark that is not effective is passed over: the next one above counts.
    $BOB = analyst($conn, 'zzoffbob');
    grant($conn, $A, $BOB, FilesAcl::MODIFY);
    mark($conn, 'folder', $A);          // made by V
    mark($conn, 'folder', $B, $BOB);    // made by Bob, inside it
    ok('CONTROL: the subfolder is kept by its own mark', FilesOfflineCoverage::load($conn)->folder($B) === 'self');
    $conn->prepare("UPDATE analysts SET is_active = 0 WHERE id = ?")->execute([$BOB]);
    $cov = FilesOfflineCoverage::load($conn);
    ok('its maker deactivated: the folder above still keeps it, and what is below', $cov->folder($B) === 'folder' && $cov->folder($C) === 'folder'
       && isset(coveredKeys($conn)[$c1['key']]));
    $conn->prepare("UPDATE analysts SET is_active = 1 WHERE id = ?")->execute([$BOB]);
    revoke($conn, $A, $BOB);
    $cov = FilesOfflineCoverage::load($conn);
    ok('...and the same when its maker can no longer see it', $cov->folder($B) === 'folder' && isset(coveredKeys($conn)[$b1v2['key']]));
    $conn->exec("DELETE FROM files_offline");
    // An exclusion below a mark that covers nothing: not shown as left out, and dropped.
    mark($conn, 'folder', $B, $D);
    $conn->prepare("INSERT INTO files_offline (target_type, target_id, excluded, marked_by) VALUES ('folder', ?, 1, ?)")->execute([$C, $V]);
    ok('an exclusion below a mark that covers nothing is not "left out"', FilesOfflineCoverage::load($conn)->folder($C) === null);
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and the job drops it', (int)$conn->query("SELECT COUNT(*) FROM files_offline WHERE excluded = 1")->fetchColumn() === 0);
    $conn->exec("DELETE FROM files_offline");

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
    putCopy($conn, $x1);
    $tmpRead = tempnam(sys_get_temp_dir(), 'zzrd');
    try { filesReadToLocal($conn, $x1['key'], $x1['size'], $tmpRead); $got = (string)file_get_contents($tmpRead); }
    catch (Throwable $e) { $got = get_class($e) . ': ' . $e->getMessage(); }
    @unlink($tmpRead);
    ok('a whole-file read (Attach as a copy) uses the copy while S3 is down', $got === $x1['bytes'], $got);
    $fake->down = false;
    // A copy that cannot be read when it is served (removed between the check and the read).
    $vp = putCopy($conn, $x1);
    chmod($vp, 0);
    $probe = @fopen($vp, 'rb');
    if ($probe !== false) {
        fclose($probe);
        ok('(not checked: running as root, a copy cannot be made unreadable) a vanished copy falls back to S3', true);
    } else {
        $fake->reads = 0;
        [$st, $out] = serve($conn, $x1);
        ok('a copy gone by the time it is read: S3 serves the file instead', $st === 0 && $out === $x1['bytes'] && $fake->reads === 1, "status $st, reads {$fake->reads}");
        $fake->down = true;
        [$st] = serve($conn, $x1);
        $fake->down = false;
        ok('...and with S3 down as well: unavailable (503)', $st === 503, "status $st");
    }
    chmod($vp, 0644);
    @unlink($vp);
    useFake(null);
    $loc = item($conn, $store, $X, 'zz-local.txt');
    putCopy($conn, $loc, str_repeat('Z', $loc['size']));
    [$st, $out] = serve($conn, $loc);
    ok('a folder backend never reads offline copies', $st === 0 && $out === $loc['bytes'], "'$out'");
    @unlink(filesOfflinePath($conn, $loc['key']));

    // ── Who may change what is kept offline ────────────────────────────
    grant($conn, $A, $U, FilesAcl::VIEW);
    grant($conn, $X, $U, FilesAcl::VIEW);
    ok('a folder backend refuses marking', str_contains(refused(fn() => FilesOfflineService::mark($conn, $V, 'item', $x1['id'])), 'S3'));
    useFake($fake);
    ok('no access: marking is refused as not found', refused(fn() => FilesOfflineService::mark($conn, $N, 'folder', $A)) === 'Folder not found.');
    ok('View only: marking is refused (Modify is needed)', str_contains(refused(fn() => FilesOfflineService::mark($conn, $U, 'folder', $A)), 'Modify'));
    foreach (['mark', 'unmark', 'exclude', 'include'] as $fn) {
        ok("analyst 0: $fn is refused", str_contains(refused(fn() => FilesOfflineService::$fn($conn, 0, 'folder', $A)), 'analyst'));
    }
    ok('analyst 0: Remove all is refused', str_contains(refused(fn() => FilesOfflineService::clearAll($conn, 0)), 'analyst'));
    ok('analyst 0: the limit is refused', str_contains(refused(fn() => FilesOfflineService::setLimit($conn, -1, 0)), 'analyst'));
    ok('...and nothing was marked by any of them', (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn() === 0);

    $r = FilesOfflineService::mark($conn, $V, 'item', $x1['id']);
    ok('Modify is enough to mark a file, and it is copied at once', $r['ready'] === true && filesOfflineHasCopy($conn, $x1['key'], $x1['size']), json_encode($r));
    ok('...with the right bytes, recorded as ready', file_get_contents(filesOfflinePath($conn, $x1['key'])) === $x1['bytes'] && (copyRow($conn, $x1['key'])['state'] ?? '') === 'ready');
    $s = $conn->prepare("SELECT COUNT(*) FROM files_audit WHERE action = 'offline' AND item_id = ? AND analyst_id = ?");
    $s->execute([$x1['id'], $V]);
    ok('marking is in the audit trail', (int)$s->fetchColumn() === 1);
    FilesOfflineService::mark($conn, $V, 'item', $x1['id']);
    $s->execute([$x1['id'], $V]);
    ok('marking twice is harmless (one mark, one audit row)', (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn() === 1 && (int)$s->fetchColumn() === 1);
    ok('View only: removing someone else\'s mark is refused', str_contains(refused(fn() => FilesOfflineService::unmark($conn, $U, 'item', $x1['id'])), 'Modify'));
    grant($conn, $X, $ADM, FilesAcl::VIEW);
    FilesOfflineService::unmark($conn, $ADM, 'item', $x1['id']);
    ok('the Files storage permission with View is enough to remove anyone\'s mark', (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn() === 0 && !is_file(filesOfflinePath($conn, $x1['key'])));

    // ── The job ────────────────────────────────────────────────────────
    $r = FilesOfflineService::mark($conn, $V, 'folder', $A);
    ok('marking a folder leaves the copying to the job', $r['ready'] === false);
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('the job copies everything the folder covers', filesOfflineHasCopy($conn, $a1['key'], $a1['size']) && filesOfflineHasCopy($conn, $b1v2['key'], $b1v2['size'])
        && filesOfflineHasCopy($conn, $c1['key'], $c1['size']) && $y['copied'] === 3 && $y['failed'] === 0 && $y['done'], json_encode($y));
    ok('...but not an old version, nor what the person who marked it cannot see', !is_file(filesOfflinePath($conn, $b1['key'])) && !is_file(filesOfflinePath($conn, $h1['key'])));
    ok('usage is read from the records', FilesOfflineService::usage($conn) == ['files' => 3, 'bytes' => $a1['size'] + $b1v2['size'] + $c1['size']], json_encode(FilesOfflineService::usage($conn)));

    $conn->prepare("UPDATE files_versions SET sha256 = ? WHERE storage_path = ?")->execute([str_repeat('0', 64), $c1['key']]);
    FilesOfflineService::forgetKey($conn, $c1['key']);
    $y = FilesOfflineService::sync($conn, time() + 60);
    $tmps = glob(dirname(filesOfflinePath($conn, $c1['key'])) . '/*.{tmp,part}', GLOB_BRACE) ?: [];
    ok('a copy that does not match its SHA-256 is not kept (recorded as failed)', $y['failed'] === 0 && $y['skipped'] === 1 && !is_file(filesOfflinePath($conn, $c1['key']))
        && !$tmps && (copyRow($conn, $c1['key'])['state'] ?? '') === 'failed', json_encode($y));
    $fake->reads = 0;
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('...and not downloaded again on the next run', $fake->reads === 0 && $y['skipped'] === 1, json_encode($y));
    $conn->prepare("UPDATE files_versions SET sha256 = ? WHERE storage_path = ?")->execute([hash('sha256', $c1['bytes']), $c1['key']]);
    $conn->prepare("DELETE FROM files_offline_copies WHERE storage_path = ?")->execute([$c1['key']]);

    $fake->down = true;
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('S3 down: the job stops filling, without an exception', !$y['done'] && $y['copied'] === 0, json_encode($y));
    $fake->down = false;
    FilesOfflineService::sync($conn, time() + 60);

    // x2 shares a1's stored file. Mark x2, then remove A's mark: the copy must stay.
    FilesOfflineService::mark($conn, $V, 'item', $x2['id']);
    $r = FilesOfflineService::unmark($conn, $V, 'folder', $A);
    ok('removing a mark deletes copies nothing else covers, and their records', !is_file(filesOfflinePath($conn, $b1v2['key'])) && !is_file(filesOfflinePath($conn, $c1['key']))
       && copyRow($conn, $c1['key']) === null, json_encode($r));
    ok('...but keeps one another kept file shares', filesOfflineHasCopy($conn, $a1['key'], $a1['size']));
    FilesOfflineService::unmark($conn, $V, 'item', $x2['id']);
    ok('...until that one is removed too', !is_file(filesOfflinePath($conn, $a1['key'])) && copyRow($conn, $a1['key']) === null);

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
    grant($conn, $X, $V, FilesAcl::FULL);
    softDelete($conn, 'item', $gone['id']);
    FilesRecycleService::purge($conn, $V, 'item', $gone['id']);
    ok('deleting permanently removes the copy and its record at once', !is_file(filesOfflinePath($conn, $gone['key'])) && copyRow($conn, $gone['key']) === null);

    $Z = folder($conn, null, 'ZZ Off Z');
    mark($conn, 'folder', $Z);
    $conn->prepare("DELETE FROM files_folders WHERE id = ?")->execute([$Z]);
    FilesAcl::reset();
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('marks on things that no longer exist are dropped', $y['marks_dropped'] === 1, json_encode($y));

    // A copy on disk that no record knows is removed; a record whose file is gone is forgotten.
    $orphan = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    $op = filesOfflinePath($conn, $orphan);
    file_put_contents($op, 'not recorded');
    touch($op, time() - 60);
    unlink(filesOfflinePath($conn, $x2['key']));
    FilesOfflineService::sync($conn, time() + 60);
    ok('a copy no record knows is removed by the job', !is_file($op));
    ok('a record whose file has gone is made good again (copied again)', filesOfflineHasCopy($conn, $x2['key'], $x2['size']));
    $late = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    $lp = filesOfflinePath($conn, $late);
    file_put_contents($lp, 'written during the run');
    touch($lp, time() + 30);
    FilesOfflineService::sync($conn, time() + 60);
    ok('a copy newer than the run\'s start is not removed by that run', is_file($lp));
    @unlink($lp);

    // ── Uploads ────────────────────────────────────────────────────────
    $part = "$store/zz-upload.part";
    file_put_contents($part, 'uploaded bytes');
    $newKey = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    $tmpUp = FilesOfflineService::keepUploadCopy($conn, $X, null, $part, $newKey);
    ok('an upload into a covered folder keeps a hard link while it is stored (no copying)', is_string($tmpUp) && @fileinode($tmpUp) === @fileinode($part) && !is_file(filesOfflinePath($conn, $newKey)));
    @unlink($part); file_put_contents($part, 'uploaded bytes');   // the upload moved its part away
    FilesOfflineService::commitUploadCopy($conn, $tmpUp, $newKey);
    ok('...and lands, recorded, once the upload is saved', (string)@file_get_contents(filesOfflinePath($conn, $newKey)) === 'uploaded bytes'
       && (copyRow($conn, $newKey)['state'] ?? '') === 'ready' && !is_file((string)$tmpUp));
    $otherKey = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    ok('...one into an uncovered folder keeps nothing', FilesOfflineService::keepUploadCopy($conn, $B, null, $part, $otherKey) === null);
    setSetting($conn, 'files_offline_max_bytes', (string)((int)FilesOfflineService::usage($conn)['bytes'] + 3));
    useFake($fake);
    $conn->exec("DELETE FROM files_offline_folders");
    ok('an upload copy is not kept when it would go past the limit', FilesOfflineService::keepUploadCopy($conn, $X, null, $part, $otherKey) === null);
    ok('...and the folder\'s tick says it is still to be copied', (int)$conn->query("SELECT state FROM files_offline_folders WHERE folder_id = " . (int)$X)->fetchColumn() === 2);
    setSetting($conn, 'files_offline_max_bytes', null);
    useFake($fake);
    FilesOfflineService::$minFreeBytes = PHP_INT_MAX;
    ok('an upload copy is not kept when it would leave too little free disk', FilesOfflineService::keepUploadCopy($conn, $X, null, $part, $otherKey) === null);
    FilesOfflineService::$minFreeBytes = 1024 * 1024 * 1024;
    FilesOfflineService::commitUploadCopy($conn, null, $otherKey);   // nothing kept: harmless
    $stray = filesOfflinePath($conn, $otherKey) . '.abc123abc123.tmp';
    file_put_contents($stray, 'left by a failed upload');
    ok('a leftover temporary copy keeps the job needed', filesOfflineHasAnyCopy($conn) === true);
    @unlink($stray);

    // ── Limits: the instant size, the free-disk floor ───────────────────
    $big = item($conn, $s3dir, $A, 'zz-big.txt');
    FilesOfflineService::$instantMaxBytes = 4;
    $r = FilesOfflineService::mark($conn, $V, 'item', $big['id']);
    FilesOfflineService::$instantMaxBytes = 64 * 1024 * 1024;
    ok('a file above the instant limit is not copied in the request', $r['ready'] === false, json_encode($r));
    FilesOfflineService::$minFreeBytes = PHP_INT_MAX;
    $y = FilesOfflineService::sync($conn, time() + 60);
    FilesOfflineService::$minFreeBytes = 1024 * 1024 * 1024;
    ok('too little free disk: nothing is copied, the run says so', $y['copied'] === 0 && $y['failed'] >= 1 && !$y['done'] && $y['disk_full'], json_encode($y));
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('...and copying resumes once there is room', $y['copied'] === 1 && filesOfflineHasCopy($conn, $big['key'], $big['size']), json_encode($y));

    // ── Exclusions (the nearest mark wins) and removing every mark ────────
    $conn->exec("DELETE FROM files_offline");
    FilesOfflineService::sync($conn, time() + 60);
    $E  = folder($conn, null, 'ZZ Off E');    // marked
    $E2 = folder($conn, $E, 'ZZ Off E2');      // excluded
    $E3 = folder($conn, $E2, 'ZZ Off E3');     // marked again, inside the excluded one
    $e1  = item($conn, $s3dir, $E, 'zz-e1.txt');
    $e1x = item($conn, $s3dir, $E, 'zz-e1x.txt');
    $e2  = item($conn, $s3dir, $E2, 'zz-e2.txt');
    $e3  = item($conn, $s3dir, $E3, 'zz-e3.txt');
    $copied = fn(array $it) => filesOfflineHasCopy($conn, $it['key'], $it['size']);
    FilesOfflineService::mark($conn, $V, 'folder', $E);
    FilesOfflineService::sync($conn, time() + 60);
    ok('CONTROL: everything under the marked folder has a copy', $copied($e1) && $copied($e1x) && $copied($e2) && $copied($e3));
    ok('excluding what is marked itself is refused (remove it instead)', str_contains(refused(fn() => FilesOfflineService::exclude($conn, $V, 'folder', $E)), 'Remove offline copy'));
    ok('excluding what no folder keeps is refused', str_contains(refused(fn() => FilesOfflineService::exclude($conn, $V, 'item', $x1['id'])), 'not kept offline'));
    FilesOfflineService::exclude($conn, $V, 'item', $e1x['id']);
    FilesOfflineService::exclude($conn, $V, 'folder', $E2);
    FilesOfflineService::mark($conn, $V, 'folder', $E3);
    $keys = coveredKeys($conn);
    ok('nearest mark wins: an excluded file and an excluded folder\'s files are not covered', !isset($keys[$e1x['key']]) && !isset($keys[$e2['key']]) && isset($keys[$e1['key']]));
    ok('...and a folder marked inside an excluded one is', isset($keys[$e3['key']]));
    $cov = FilesOfflineCoverage::load($conn);
    ok('states: excluded shows as excluded; what is under it is not covered', $cov->folder($E2) === 'excluded' && $cov->folder($E3) === 'self'
       && $cov->item($e1x['id'], $E) === 'excluded' && $cov->item($e2['id'], $E2) === null);
    ok('excluding removes the copies at once', !is_file(filesOfflinePath($conn, $e1x['key'])) && !is_file(filesOfflinePath($conn, $e2['key'])) && $copied($e1));
    FilesOfflineService::include($conn, $V, 'item', $e1x['id']);
    FilesOfflineService::sync($conn, time() + 60);
    ok('keep offline again: covered and copied again', $copied($e1x));
    FilesOfflineService::mark($conn, $V, 'folder', $E2);
    ok('marking an excluded folder keeps it offline', FilesOfflineCoverage::load($conn)->folder($E2) === 'self');
    FilesOfflineService::exclude($conn, $V, 'item', $e1['id']);
    $sum = FilesOfflineService::summary($conn);
    ok('the Storage tab\'s summary counts marks and exclusions', $sum['folders'] === 3 && $sum['files'] === 0 && $sum['excluded'] === 1 && $sum['people'] === 1 && $sum['inactive'] === 0, json_encode($sum));
    mark($conn, 'item', $e1x['id'], $D);
    $conn->prepare("INSERT INTO files_offline (target_type, target_id, excluded, marked_by) VALUES ('item', ?, 1, ?)")->execute([$e3['id'], $U]);
    $sum = FilesOfflineService::summary($conn);
    ok('...people: the makers of marks only, not of exclusions; marks by people no longer active counted', $sum['people'] === 2 && $sum['inactive'] === 1 && $sum['excluded'] === 2, json_encode($sum));
    FilesOfflineService::clearAll($conn, $ADM);
    ok('remove all: every mark and exclusion is gone', (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn() === 0);
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and the job removes every copy and record, so files are read from S3 only', filesOfflineHasAnyCopy($conn) === false
       && (int)$conn->query("SELECT COUNT(*) FROM files_offline_copies")->fetchColumn() === 0);

    // ── Exclusions nothing covers any more are dropped ─────────────────
    $SA = folder($conn, null, 'ZZ Off SA');
    $SB = folder($conn, null, 'ZZ Off SB');
    $sf = item($conn, $s3dir, $SA, 'zz-sf.txt');
    $exRows = function (int $itemId) use ($conn): int {
        $q = $conn->prepare("SELECT COUNT(*) FROM files_offline WHERE target_type = 'item' AND target_id = ? AND excluded = 1");
        $q->execute([$itemId]);
        return (int)$q->fetchColumn();
    };
    FilesOfflineService::mark($conn, $V, 'folder', $SA);
    FilesOfflineService::exclude($conn, $V, 'item', $sf['id']);
    FilesOfflineService::unmark($conn, $V, 'folder', $SA);
    ok('removing the mark above drops the exclusions under it', $exRows($sf['id']) === 0);
    FilesOfflineService::mark($conn, $V, 'folder', $SA);
    FilesOfflineService::exclude($conn, $V, 'item', $sf['id']);
    $conn->prepare("UPDATE files_items SET folder_id = ? WHERE id = ?")->execute([$SB, $sf['id']]);
    FilesAcl::reset();
    ok('a left-out file moved where nothing keeps it is not shown as "left out"', FilesOfflineCoverage::load($conn)->item($sf['id'], $SB) === null);
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and the job drops that exclusion', $exRows($sf['id']) === 0);
    $conn->prepare("UPDATE files_items SET folder_id = ? WHERE id = ?")->execute([$SA, $sf['id']]);
    FilesAcl::reset();
    FilesOfflineService::exclude($conn, $V, 'item', $sf['id']);
    $nk = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    ok('a new version of a left-out file keeps no upload copy', FilesOfflineService::keepUploadCopy($conn, $SA, $sf['id'], $part, $nk) === null);
    $conn->exec("DELETE FROM files_offline");

    // ── Ticks: the states, as each viewer may know them ─────────────────
    FilesOfflineService::sync($conn, time() + 60);
    $T  = folder($conn, null, 'ZZ Off T');
    $T2 = folder($conn, $T, 'ZZ Off T2');
    $t1 = item($conn, $s3dir, $T, 'zz-t1.txt');
    $t2 = item($conn, $s3dir, $T2, 'zz-t2.txt');
    FilesOfflineService::mark($conn, $V, 'folder', $T);
    $lv = fn(int $who) => FilesAcl::levels($conn, $who);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2, $X]);
    ok('a folder whose files are still being copied is not shown as available', ($fs[$T] ?? null) === 'pending' && ($fs[$T2] ?? null) === 'pending' && !isset($fs[$X]), json_encode($fs));
    ok('...nor is a file in it', itemState($conn, $t2) === 'pending');
    FilesOfflineService::sync($conn, time() + 60);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2]);
    ok('once the job has copied everything under it, the folder is available', $fs === [$T => 'ready', $T2 => 'ready'] && itemState($conn, $t2) === 'ready', json_encode($fs));
    // A file restored from the recycle bin into a folder recorded as ready: its copy went
    // while it was in the bin, so the folder is not available offline until the job has run.
    softDelete($conn, 'item', $t2['id']);
    FilesOfflineService::sync($conn, time() + 60);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2]);
    ok('CONTROL: with its only file in the recycle bin, the folder is recorded as ready', ($fs[$T2] ?? null) === 'ready' && !is_file(filesOfflinePath($conn, $t2['key'])), json_encode($fs));
    FilesRecycleService::restore($conn, $V, 'item', $t2['id']);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2]);
    ok('a file restored from the recycle bin into it: the folder shows it is being made available', ($fs[$T2] ?? null) === 'pending' && ($fs[$T] ?? null) === 'pending', json_encode($fs));
    FilesOfflineService::sync($conn, time() + 60);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2]);
    ok('...and available again once the job has copied it', $fs === [$T => 'ready', $T2 => 'ready'], json_encode($fs));
    $t3 = item($conn, $s3dir, $T2, 'zz-t3.txt');
    unlink("$s3dir/{$t3['key']}");   // missing from S3: its copy fails
    FilesOfflineService::sync($conn, time() + 60);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2]);
    ok('a file whose copy failed says so, rather than "being made available"', itemState($conn, $t3) === 'failed');
    ok('...and so do the folders above it', $fs === [$T => 'failed', $T2 => 'failed'], json_encode($fs));
    $t4 = item($conn, $s3dir, $T, 'zz-t4.txt');
    $fake->down = true;   // the job cannot copy it, and works out the ticks at the end of its run
    FilesOfflineService::sync($conn, time() + 60);
    $fake->down = false;
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), $lv($V), [$T, $T2]);
    ok('a file still waiting for its copy outweighs one that failed', ($fs[$T] ?? null) === 'pending' && ($fs[$T2] ?? null) === 'failed', json_encode($fs));
    $conn->prepare("UPDATE files_offline_copies SET failed_datetime = UTC_TIMESTAMP() - INTERVAL 2 DAY WHERE storage_path = ?")->execute([$t3['key']]);
    ok('once its day of waiting is over, a failed file is being copied again', itemState($conn, $t3) === 'pending');
    // The viewer: a subfolder the person who marked can see, but this viewer cannot.
    $TS = folder($conn, $T, 'ZZ Off TS (private)', false);
    grant($conn, $TS, $V, FilesAcl::VIEW);
    grant($conn, $T, $U, FilesAcl::VIEW);
    $ts1 = item($conn, $s3dir, $TS, 'zz-ts1.txt');
    softDelete($conn, 'item', $t3['id']); softDelete($conn, 'item', $t4['id']);
    FilesOfflineService::sync($conn, time() + 60);
    $conn->prepare("UPDATE files_offline_copies SET state = 'failed', failed_datetime = UTC_TIMESTAMP() WHERE storage_path = ?")->execute([$ts1['key']]);
    FilesOfflineService::sync($conn, time() + 60);   // waits out its day; the ticks are worked out again
    $cov = FilesOfflineCoverage::load($conn);
    $fsV = filesOfflineFolderStates($conn, $cov, $lv($V), [$T]);
    $fsU = filesOfflineFolderStates($conn, $cov, $lv($U), [$T]);
    ok('a folder\'s tick counts a failing subfolder for someone who can see it', ($fsV[$T] ?? null) === 'failed', json_encode($fsV));
    ok('...and not for someone who cannot (it does not show through)', ($fsU[$T] ?? null) === 'ready', json_encode($fsU));
    $conn->exec("DELETE FROM files_offline");

    // During a move from S3 back to a folder, a file already moved is available offline:
    // its bytes are on this server, so no copy is made - and none is waited for.
    $mv = item($conn, $s3dir, $T, 'zz-mv.txt');
    @mkdir(dirname("$store/{$mv['key']}"), 0777, true);
    copy("$s3dir/{$mv['key']}", "$store/{$mv['key']}");
    $notyet = item($conn, $s3dir, $T, 'zz-notyet.txt');
    $conn->prepare("INSERT INTO storage_migration_items (store, object_key, size_bytes, state) VALUES ('files', ?, ?, 'verified'), ('files', ?, ?, 'pending')")
         ->execute([$mv['key'], $mv['size'], $notyet['key'], $notyet['size']]);
    filesStorageReset();
    FilesStorageCache::$drivers['previous'] = $fake;   // active = the folder, previous = "S3"
    $r = FilesOfflineService::mark($conn, $V, 'item', $mv['id']);
    ok('during a move to a folder: a file already moved counts as available offline', $r['ready'] === true && itemState($conn, $mv) === 'ready'
       && !is_file(filesOfflinePath($conn, $mv['key'])), json_encode($r));
    mark($conn, 'item', $notyet['id']);
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and one still in S3 is copied', filesOfflineHasCopy($conn, $notyet['key'], $notyet['size']) && !is_file(filesOfflinePath($conn, $mv['key'])));
    $conn->exec("DELETE FROM storage_migration_items WHERE store = 'files'");
    $conn->exec("DELETE FROM files_offline");
    useFake($fake);

    // ── A very large file never holds the job past its time ───────────────
    // The fetch stops at the deadline and keeps what it has (<copy>.part); the next run
    // carries on from there. 3 MB: more than one 1 MB read, so it can stop part-way.
    FilesOfflineService::sync($conn, time() + 60);
    $hugeBytes = random_bytes(3 * 1024 * 1024 + 123);
    $huge = item($conn, $s3dir, $T, 'zz-huge.bin', stored($s3dir, $hugeBytes));
    $hugePart = filesOfflinePath($conn, $huge['key']) . '.part';
    try { FilesOfflineService::copyKey($conn, $huge['key'], $huge['size'], hash('sha256', $hugeBytes), time() - 1); $err = null; }
    catch (Throwable $e) { $err = $e; }
    clearstatcache();
    ok('a copy that runs out of time stops part-way and keeps what it fetched', $err instanceof FilesOfflineOutOfTime && is_file($hugePart)
       && filesize($hugePart) > 0 && filesize($hugePart) < $huge['size'] && !is_file(filesOfflinePath($conn, $huge['key'])));
    ok('...a part-way copy is never served, but keeps the job needed', filesOfflineHasCopy($conn, $huge['key'], $huge['size']) === false && filesOfflineHasAnyCopy($conn) === true);
    mark($conn, 'item', $huge['id']);
    $y = FilesOfflineService::sync($conn, time() + 60);
    clearstatcache();
    ok('...the next run carries on from there and finishes it, checked', $y['copied'] === 1 && $y['skipped'] === 0 && !is_file($hugePart)
       && (string)@file_get_contents(filesOfflinePath($conn, $huge['key'])) === $hugeBytes, json_encode($y));
    $huge2Bytes = random_bytes(3 * 1024 * 1024 + 7);
    $huge2 = item($conn, $s3dir, $T, 'zz-huge2.bin', stored($s3dir, $huge2Bytes));
    mark($conn, 'item', $huge2['id']);
    $fake->delay = 3;   // S3 is slow to start: the deadline passes during the copy
    $y = FilesOfflineService::sync($conn, time() + 2);
    $fake->delay = 0;
    clearstatcache();
    ok('the job ends on time in the middle of a big file: more to do, not a failure', !$y['done'] && $y['failed'] === 0 && $y['skipped'] === 0
       && is_file(filesOfflinePath($conn, $huge2['key']) . '.part') && copyRow($conn, $huge2['key']) === null, json_encode($y));
    ok('...and the file shows as still being copied', itemState($conn, $huge2) === 'pending');
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('...the next run finishes it', $y['copied'] === 1 && filesOfflineHasCopy($conn, $huge2['key'], $huge2['size']), json_encode($y));
    $conn->exec("DELETE FROM files_offline");
    $stale = filesOfflinePath($conn, $huge2['key']) . '.part';
    file_put_contents($stale, 'part-way');
    FilesOfflineService::sync($conn, time() + 60);
    ok('a part-way copy of something no longer kept offline is removed', !is_file($stale));
    softDelete($conn, 'item', $huge['id']); softDelete($conn, 'item', $huge2['id']);

    // ── The administrator's limit ───────────────────────────────────────
    ok('the limit must be one of the choices', str_contains(refused(fn() => FilesOfflineService::setLimit($conn, $ADM, 7)), 'list'));
    FilesOfflineService::setLimit($conn, $ADM, 10);
    ok('a limit chosen is saved (in bytes), and audited', filesOfflineLimit($conn) === 10 * 1000 * 1000 * 1000);
    FilesOfflineService::setLimit($conn, $ADM, 0);
    ok('...and "No limit" clears it', filesOfflineLimit($conn) === null);
    $L1 = folder($conn, null, 'ZZ Off L');
    $l1 = item($conn, $s3dir, $L1, 'zz-l1.txt');
    $l2 = item($conn, $s3dir, $L1, 'zz-l2.txt');
    $l3 = item($conn, $s3dir, $L1, 'zz-l3.txt');
    setSetting($conn, 'files_offline_max_bytes', (string)($l1['size'] + 5));   // room for one file
    useFake($fake);
    FilesOfflineService::mark($conn, $V, 'item', $l1['id']);
    $msg = refused(fn() => FilesOfflineService::mark($conn, $V, 'item', $l2['id']));
    ok('marking that would go past the limit is refused, and leaves no mark', str_contains($msg, 'limit')
       && (int)$conn->query("SELECT COUNT(*) FROM files_offline WHERE target_type = 'item' AND target_id = " . (int)$l2['id'])->fetchColumn() === 0, $msg);
    ok('...a folder too', str_contains(refused(fn() => FilesOfflineService::mark($conn, $V, 'folder', $L1)), 'limit'));
    mark($conn, 'folder', $L1);   // as if marked before the limit was set
    $y = FilesOfflineService::sync($conn, time() + 60);
    useFake($fake);
    ok('the job stops copying at the limit and says so', $y['limit_reached'] && $y['copied'] === 0 && filesSetting($conn, 'files_offline_limit_reached') === '1', json_encode($y));
    setSetting($conn, 'files_offline_max_bytes', null);
    useFake($fake);
    $y = FilesOfflineService::sync($conn, time() + 60);
    useFake($fake);
    ok('...and carries on once it is raised, clearing the notice', $y['copied'] === 2 && !$y['limit_reached'] && filesSetting($conn, 'files_offline_limit_reached') === '', json_encode($y));
    $conn->exec("DELETE FROM files_offline");

    // ── Versions against copies: Overwrite, Restore version, the tidy-up ───
    FilesOfflineService::sync($conn, time() + 60);
    $W = folder($conn, null, 'ZZ Off W');
    $vid = function (int $itemId, int $no) use ($conn): int {
        $q = $conn->prepare("SELECT id FROM files_versions WHERE item_id = ? AND version_no = ?");
        $q->execute([$itemId, $no]);
        return (int)$q->fetchColumn();
    };
    $ow  = item($conn, $s3dir, $W, 'zz-ow.txt');
    $ows = item($conn, $s3dir, $W, 'zz-ow-shared.txt');
    item($conn, $s3dir, $W, 'zz-ow-share.txt', $ows['key']);   // shares ows's bytes
    FilesOfflineService::mark($conn, $V, 'folder', $W);
    FilesOfflineService::sync($conn, time() + 60);
    ok('CONTROL: version 1 of each has a copy', filesOfflineHasCopy($conn, $ow['key'], $ow['size']) && filesOfflineHasCopy($conn, $ows['key'], $ows['size']));
    $ow2  = newVersion($conn, $s3dir, $ow);
    $ows2 = newVersion($conn, $s3dir, $ows);
    FilesVersionsService::overwrite($conn, $V, filesItem($conn, $ow['id']), $vid($ow['id'], 2));
    FilesVersionsService::overwrite($conn, $V, filesItem($conn, $ows['id']), $vid($ows['id'], 2));
    ok('Overwrite: the replaced version\'s copy and record go at once', !is_file(filesOfflinePath($conn, $ow['key'])) && copyRow($conn, $ow['key']) === null);
    ok('...unless another file still uses the same stored bytes', filesOfflineHasCopy($conn, $ows['key'], $ows['size']));
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and the job copies the new version', filesOfflineHasCopy($conn, $ow2['key'], $ow2['size']) && filesOfflineHasCopy($conn, $ows2['key'], $ows2['size']));
    $rs  = item($conn, $s3dir, $W, 'zz-rs.txt');
    FilesOfflineService::sync($conn, time() + 60);
    $rs2 = newVersion($conn, $s3dir, $rs);
    FilesOfflineService::sync($conn, time() + 60);
    ok('CONTROL: after a new version, only the current one has a copy', filesOfflineHasCopy($conn, $rs2['key'], $rs2['size']) && !is_file(filesOfflinePath($conn, $rs['key'])));
    FilesOfflineService::sync($conn, time() + 60);   // the folder's tick: ready
    FilesVersionsService::restore($conn, $V, filesItem($conn, $rs['id']), $vid($rs['id'], 1));
    ok('Restore version: the folder shows it is being made available until the job has run', (filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), FilesAcl::levels($conn, $V), [$W])[$W] ?? null) === 'pending');
    FilesOfflineService::sync($conn, time() + 60);
    ok('Restore version: the restored bytes are copied, the replaced version\'s copy goes', filesOfflineHasCopy($conn, $rs['key'], $rs['size']) && !is_file(filesOfflinePath($conn, $rs2['key'])));
    putCopy($conn, $rs2);   // as if the job had not tidied it yet
    $dropped = FilesVersionsService::applyKeep($conn, $rs['id'], 1);
    ok('the versions tidy-up: an old version\'s copy goes with its bytes', $dropped === 2 && !is_file(filesOfflinePath($conn, $rs2['key'])), "dropped $dropped");
    ok('...and the current version (restored, sharing version 1\'s bytes) keeps its copy', filesOfflineHasCopy($conn, $rs['key'], $rs['size']));
    $conn->exec("DELETE FROM files_offline");

    // ── A new storage folder: the old folder's copies, emptied by the job ──
    $extraDirs[] = $or = sys_get_temp_dir() . '/zz-off-or-' . bin2hex(random_bytes(4));
    $ok1 = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    @mkdir("$or/offline/2026/11/11", 0777, true);
    file_put_contents("$or/offline/$ok1", 'old copy');
    file_put_contents("$or/offline/$ok1.part", 'part-way copy');
    file_put_contents("$or/offline/keep-me.txt", 'not ours');
    $conn->exec("INSERT INTO files_offline_copies (storage_path, size_bytes, state) VALUES ('2026/11/11/" . bin2hex(random_bytes(16)) . ".bin', 1, 'ready')");
    $rowsBefore = (int)$conn->query("SELECT COUNT(*) FROM files_offline_copies")->fetchColumn();
    FilesOfflineService::storageFolderChanged($conn, $or, "$store-elsewhere", 'same');
    ok('the same place under another name: nothing changes', FilesOfflineService::oldRoots($conn) === [] && $rowsBefore > 0
       && (int)$conn->query("SELECT COUNT(*) FROM files_offline_copies")->fetchColumn() === $rowsBefore);
    FilesOfflineService::storageFolderChanged($conn, $or, "$store-elsewhere", 'unknown');
    ok('cannot tell whether it is another place: queued as unproven, the records kept', FilesOfflineService::oldRoots($conn) === [['root' => $or, 'proven' => false]]
       && (int)$conn->query("SELECT COUNT(*) FROM files_offline_copies")->fetchColumn() === $rowsBefore);
    FilesOfflineService::sync($conn, time() + 60);
    ok('...and the job never empties an unproven folder', is_file("$or/offline/$ok1") && FilesOfflineService::oldRoots($conn) === [['root' => $or, 'proven' => false]]);
    ok('...nor is it needed for one', !str_contains(jobSettingStrict($conn, 'files_offline_old_roots'), '"proven":true'));
    $res = FilesOfflineService::removeOldRoot($conn, $ADM, $or);   // Remove: probed again - another temporary folder, so different
    ok('Remove probes again; proved different, it is queued for the job', $res === ['result' => 'queued'] && FilesOfflineService::oldRoots($conn) === [['root' => $or, 'proven' => true]], json_encode($res));
    ok('Remove on a folder not waiting is refused', str_contains(refused(fn() => FilesOfflineService::removeOldRoot($conn, $ADM, '/nowhere')), 'not waiting'));
    ok('Remove needs a real analyst', str_contains(refused(fn() => FilesOfflineService::removeOldRoot($conn, 0, $or)), 'analyst'));
    FilesOfflineService::storageFolderChanged($conn, $or, "$or/offline/inner", 'different');
    ok('a new folder inside the old copies: nothing more is queued', FilesOfflineService::oldRoots($conn) === [['root' => $or, 'proven' => true]]);
    FilesOfflineService::storageFolderChanged($conn, $or, "$store-elsewhere", 'different');
    ok('proved another place: the old folder is queued, nothing deleted inside the save', FilesOfflineService::oldRoots($conn) === [['root' => $or, 'proven' => true]] && is_file("$or/offline/$ok1"));
    ok('...which keeps the job needed', jobRegistry()['files_offline_sync']['needed']($conn) === true);
    FilesOfflineService::sync($conn, time() - 1);
    ok('out of time: the job leaves it queued for the next run', FilesOfflineService::oldRoots($conn) === [['root' => $or, 'proven' => true]] && is_file("$or/offline/$ok1"));
    FilesOfflineService::sync($conn, time() + 60);
    ok('the next run deletes the old copies, part-way ones too, and forgets the folder', !is_file("$or/offline/$ok1") && !is_file("$or/offline/$ok1.part") && FilesOfflineService::oldRoots($conn) === []);
    ok('...and nothing that is not a copy', is_file("$or/offline/keep-me.txt"));
    @mkdir("$store/offline", 0777, true);
    FilesOfflineService::storageFolderChanged($conn, $store, "$store-elsewhere", 'unknown');   // as if the current folder were the old one
    $res = FilesOfflineService::removeOldRoot($conn, $ADM, $store);
    ok('Remove on what turns out to be the current folder: forgotten, nothing deleted', $res['result'] !== 'queued' && FilesOfflineService::oldRoots($conn) === [], json_encode($res));

    // An offline folder that IS the previous storage folder (storage moved from <P>/offline
    // to <P>) holds the real files of a move in progress, not copies: never removed.
    $realKey = '2026/11/11/' . bin2hex(random_bytes(16)) . '.bin';
    $realPath = "$store/offline/$realKey";
    @mkdir(dirname($realPath), 0777, true);
    file_put_contents($realPath, 'a real stored file, not a copy');
    mark($conn, 'item', $x1['id']);
    setSetting($conn, 'files_storage_previous', encryptValue(json_encode(['driver' => 'local', 'root' => "$store/offline"])));
    FilesOfflineService::sync($conn, time() + 60);
    ok('a previous storage folder inside the offline folder: its files are never deleted', is_file($realPath));
    setSetting($conn, 'files_storage_previous', null);
    @unlink($realPath);
    $conn->exec("DELETE FROM files_offline");
    useFake($fake);

    // ── Showing, and the job's health check ─────────────────────────────
    mark($conn, 'folder', $X);
    ok('the coverage to show while S3 is in use', ($c = filesOfflineDisplayCoverage($conn)) !== null && $c->folder($X) === 'self');
    useFake(null);
    ok('on a server folder: nothing to show', filesOfflineDisplayCoverage($conn) === null);
    // Copies whose records went with the storage folder change above: written a moment ago
    // in this test, so dated back, as the job leaves anything newer than its start.
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(filesOfflineRoot($conn), FilesystemIterator::SKIP_DOTS)) as $f) touch($f->getPathname(), time() - 60);
    FilesOfflineService::sync($conn, time() + 60);   // copies mean nothing here: all go
    ok('marks with Files in a server folder (and no copies left): the job is not needed', jobRegistry()['files_offline_sync']['needed']($conn) === false);
    $conn->exec("DELETE FROM files_offline");
    $nowhere = sys_get_temp_dir() . '/zz-off-nowhere-' . bin2hex(random_bytes(4));
    setSetting($conn, 'files_storage_root', $nowhere);
    useFake($fake);
    filesOfflinePath($conn, $nk);
    filesOfflineHasCopy($conn, $nk, 1);
    ok('the job\'s health check, and looking for a copy, create no folder', jobOfflineCopiesLeft($conn) === false && !is_dir($nowhere));
    setSetting($conn, 'files_storage_root', $store);
    useFake($fake);

    // ── One change at a time ───────────────────────────────────────────
    // A second connection holds the lock (as a removal or the job would): a mark waits
    // for it, then gives up with a message, rather than racing it.
    $conn2 = connectToDatabase();
    $lockName = 'freeitsm_offline_' . substr(md5($dbName), 0, 16);
    $conn2->query("SELECT GET_LOCK(" . $conn2->quote($lockName) . ", 5)");
    FilesOfflineService::$lockWait = 1;
    $msg = refused(fn() => FilesOfflineService::mark($conn, $V, 'folder', $X));
    FilesOfflineService::$lockWait = 20;
    ok('while another change holds the lock, a mark waits and then says it is busy', str_contains($msg, 'busy'), $msg);
    $conn2->query("SELECT RELEASE_LOCK(" . $conn2->quote($lockName) . ")");
    $r = FilesOfflineService::mark($conn, $V, 'folder', $X);
    ok('...and goes through once it is free', $r['ok'] === true);
    $conn2 = null;
    $conn->exec("DELETE FROM files_offline");

    // ── Scale: memory does not grow with the number of files ─────────────
    $SC = folder($conn, null, 'ZZ Off Scale');
    $n = 25000;
    $conn->exec("SET SESSION cte_max_recursion_depth = " . ($n + 10));
    $conn->exec("INSERT INTO files_items (folder_id, name, size_bytes)
                 WITH RECURSIVE seq (k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM seq WHERE k < $n)
                 SELECT $SC, CONCAT('zz-scale-', k, '.txt'), 10 FROM seq");
    $conn->exec("INSERT INTO files_versions (item_id, version_no, storage_path, size_bytes)
                 SELECT id, 1, CONCAT('2026/11/11/', MD5(CONCAT('zz', id)), '.bin'), 10 FROM files_items WHERE folder_id = $SC");
    $conn->exec("UPDATE files_items i JOIN files_versions v ON v.item_id = i.id SET i.current_version_id = v.id WHERE i.folder_id = $SC");
    // Every copy "failed" just now: the job reads them all, and copies none (no downloads in a test).
    $conn->exec("INSERT INTO files_offline_copies (storage_path, size_bytes, state, failed_datetime)
                 SELECT v.storage_path, 0, 'failed', UTC_TIMESTAMP() FROM files_versions v JOIN files_items i ON i.id = v.item_id WHERE i.folder_id = $SC");
    mark($conn, 'folder', $SC);
    gc_collect_cycles();
    $t0 = microtime(true);
    memory_reset_peak_usage();
    $base = memory_get_usage();
    $y = FilesOfflineService::sync($conn, time() + 120);
    $jobPeak = memory_get_peak_usage() - $base;
    $jobTime = microtime(true) - $t0;
    ok("the job goes through all $n in batches", $y['skipped'] === $n && $y['done'], json_encode($y));
    memory_reset_peak_usage();
    $base = memory_get_usage();
    $t1 = microtime(true);
    $fs = filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), FilesAcl::levels($conn, $V), [$SC]);
    $listTime = microtime(true) - $t1;
    $listPeak = memory_get_peak_usage() - $base;
    ok(sprintf('a folder of %d kept files: its tick from the job\'s rollup in %.3f s (under 0.2 s)', $n, $listTime), ($fs[$SC] ?? null) === 'failed' && $listTime < 0.2, json_encode($fs));
    $conn->exec("DELETE FROM files_offline_copies WHERE state = 'failed' LIMIT 1");
    ok('...which reads the rollup, not the files (a change shows after the next run)', (filesOfflineFolderStates($conn, FilesOfflineCoverage::load($conn), FilesAcl::levels($conn, $V), [$SC])[$SC] ?? null) === 'failed');
    memory_reset_peak_usage();
    $base = memory_get_usage();
    $r = FilesOfflineService::unmark($conn, $V, 'folder', $SC);
    $unmarkPeak = memory_get_peak_usage() - $base;
    ok("removing the mark forgets all $n records, in batches", (int)$conn->query("SELECT COUNT(*) FROM files_offline_copies")->fetchColumn() === 0);
    $mb = fn(int $b) => round($b / 1048576, 1) . ' MB';
    ok('...with memory bounded: list ' . $mb($listPeak) . ', job ' . $mb($jobPeak) . ', removal ' . $mb($unmarkPeak) . ' (each under 8 MB)',
       $listPeak < 8 << 20 && $jobPeak < 8 << 20 && $unmarkPeak < 8 << 20);
    printf("       (%d files: job %.1f s)\n", $n, $jobTime);
} catch (Throwable $e) {
    ok('no unexpected exception', false, get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
} finally {
    if ($conn->inTransaction()) $conn->rollBack();
    filesStorageReset();
    FilesOfflineService::$lockWait = 20;
    foreach (array_merge([$store, $s3dir], $extraDirs) as $d) rmTree($d);
}

// ── Before Database Verification: no offline tables ─────────────────────────────
// Renaming a table ends any open transaction, so this runs on its own: the tables are
// renamed, the checks run in a transaction that is rolled back, and the names go back
// (also on a fatal error, through the shutdown function above).
echo "\nBefore Database Verification (no offline tables)\n";
$store = sys_get_temp_dir() . '/zz-off-dv-' . bin2hex(random_bytes(4));
$s3dir = sys_get_temp_dir() . '/zz-off-dv-s3-' . bin2hex(random_bytes(4));
mkdir($store); mkdir($s3dir);
try {
    foreach ($hidden as $real => $zz) $conn->exec("RENAME TABLE $real TO $zz");
    $conn->beginTransaction();
    foreach (['files_storage_driver', 'files_storage_previous', 'files_storage_cleanup', 'files_offline_max_bytes', 'files_offline_old_roots'] as $k) setSetting($conn, $k, null);
    setSetting($conn, 'files_storage_root', $store);
    $fake = new ZzFakeS3($s3dir);
    useFake($fake);
    $V = analyst($conn, 'zzoffdv');
    $D1 = folder($conn, null, 'ZZ Off DV');
    $d1 = item($conn, $s3dir, $D1, 'zz-dv.txt');
    ok('marks: none (null), nothing covered', filesOfflineMarks($conn) === null && coveredKeys($conn) === [] && FilesOfflineService::usage($conn) === null);
    ok('the list shows no badges', filesOfflineDisplayCoverage($conn) === null);
    foreach (['mark', 'unmark', 'exclude', 'include'] as $fn) {
        ok("$fn: asks for Database Verification", str_contains(refused(fn() => FilesOfflineService::$fn($conn, $V, 'item', $d1['id'])), 'Database Verification'));
    }
    ok('Remove all: nothing to remove', FilesOfflineService::clearAll($conn, $V) === ['marks' => 0]);
    ok('the Storage tab\'s summary: none', FilesOfflineService::summary($conn) === null);
    ok('an upload keeps no copy, and does not fail', FilesOfflineService::keepUploadCopy($conn, $D1, null, __FILE__, $d1['key']) === null);
    $y = FilesOfflineService::sync($conn, time() + 60);
    ok('the job does nothing, without an error', $y['copied'] === 0 && $y['removed'] === 0 && $y['done'], json_encode($y));
    ok('the job is not needed', jobRegistry()['files_offline_sync']['needed']($conn) === false);
    grant($conn, $D1, $V, FilesAcl::FULL);
    softDelete($conn, 'item', $d1['id']);
    try { FilesRecycleService::purge($conn, $V, 'item', $d1['id']); $gone = !filesItem($conn, $d1['id']); $msg = ''; }
    catch (Throwable $e) { $gone = false; $msg = get_class($e) . ': ' . $e->getMessage(); }
    ok('deleting a file permanently still works', $gone, $msg);
} catch (Throwable $e) {
    ok('no unexpected exception (before Database Verification)', false, get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
} finally {
    $tablesBack();
    filesStorageReset();
    rmTree($store); rmTree($s3dir);
}
ok('the tables are back', (bool)$conn->query("SHOW TABLES LIKE 'files_offline'")->fetchColumn() && (bool)$conn->query("SHOW TABLES LIKE 'files_offline_copies'")->fetchColumn());

// ── The endpoint: api/files/offline.php over HTTP ────────────────────────────────
echo "\napi/files/offline.php\n";
$base = rtrim((string)getenv('FREEITSM_TEST_URL'), '/');
$admin = (int)$conn->query("SELECT id FROM analysts WHERE is_active = 1 AND is_admin = 1 ORDER BY id LIMIT 1")->fetchColumn();
if ($base === '' || $admin <= 0) {
    echo "  (skipped: set FREEITSM_TEST_URL, and the database needs an active administrator)\n";
} else {
    $sid  = 'zzoff' . bin2hex(random_bytes(10));
    $csrf = bin2hex(random_bytes(32));
    $sessFile = rtrim(ini_get('session.save_path') ?: sys_get_temp_dir(), "/\\") . '/sess_' . $sid;
    file_put_contents($sessFile, 'analyst_id|i:' . $admin . ';analyst_name|s:5:"ZZOFF";is_admin|i:1;csrf_token|s:64:"' . $csrf . '";');
    $call = function (string $method, ?array $body = null) use ($base, $sid, $csrf): array {
        $ch = curl_init("$base/api/files/offline.php" . ($method === 'GET' ? '?action=on&type=item&id=1' : ''));
        $opts = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_COOKIE => "PHPSESSID=$sid",
                 CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-CSRF-Token: ' . $csrf]];
        if ($method === 'POST') { $opts[CURLOPT_POST] = true; $opts[CURLOPT_POSTFIELDS] = json_encode($body); }
        curl_setopt_array($ch, $opts);
        $raw = (string)curl_exec($ch);
        return [(int)curl_getinfo($ch, CURLINFO_HTTP_CODE), $raw, json_decode($raw, true)];
    };
    try {
        $marksBefore = (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn();
        [$code, $raw] = $call('GET');
        ok('a GET is refused (405): it changes data, and a link on another site can send one', $code === 405 && str_contains($raw, 'POST'), "$code $raw");
        [$code, $raw, $r] = $call('POST', ['action' => 'zz-nonsense', 'type' => 'item', 'id' => 1]);
        ok('an unknown action is refused, saying so', ($r['success'] ?? null) === false && ($r['error'] ?? '') === 'Unknown action.', "$code $raw");
        [$code, $raw, $r] = $call('POST', ['action' => 'on', 'type' => 'zz', 'id' => 1]);
        ok('an unknown type is refused', ($r['success'] ?? null) === false && ($r['error'] ?? '') === 'Unknown item.', "$code $raw");
        [$code, $raw, $r] = $call('POST', ['action' => 'off', 'type' => 'item', 'id' => 0]);
        ok('a missing id is refused', ($r['success'] ?? null) === false && ($r['error'] ?? '') === 'Unknown item.', "$code $raw");
        [$code, $raw, $r] = $call('POST', ['action' => 'limit', 'gb' => 7]);
        ok('a limit that is not one of the choices is refused', ($r['success'] ?? null) === false && str_contains((string)($r['error'] ?? ''), 'list'), "$code $raw");
        ok('...and none of them changed anything', (int)$conn->query("SELECT COUNT(*) FROM files_offline")->fetchColumn() === $marksBefore);
    } finally {
        @unlink($sessFile);
    }
}

echo str_repeat('-', 72) . "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
