<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * Backups and the stores (#284): a store kept in S3 is backed up from the store (and an
 * unchanged file is not downloaded again), and a restore or rollback writes it back where
 * the store is kept - S3 or the server folder - deleting what the backup does not hold.
 * The rollback keeps this install's storage settings.
 *
 * ⚠️ The rollback REPLACES the test database. Run against a scratch database, as the web
 * server's user: FREEITSM_TEST_DATABASE=<db> php tests/storage-stores-backup.php
 */

$root = dirname(__DIR__);
require_once "$root/config.php";
require_once "$root/includes/functions.php";
require_once "$root/includes/storage/stores.php";
require_once "$root/includes/storage/store_migration.php";
require_once "$root/includes/services/backups.php";
require_once "$root/includes/backup/runner.php";
require_once "$root/includes/backup/restore.php";
require_once "$root/includes/backup/rollback.php";

$pass = 0; $fail = 0;
function ok(string $label, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; printf("  PASS %-70s\n", $label); }
    else       { $fail++; printf("  FAIL %-70s %s\n", $label, $detail); }
}
function section(string $t): void { echo "\n$t\n" . str_repeat('-', 72) . "\n"; }

/** S3 stand-in per store: a folder that counts its downloads. */
final class ZzBkStoreS3 implements StorageDriver, StorageLister
{
    public static int $reads = 0;
    private LocalDriver $d;
    public function __construct(string $dir) { $this->d = new LocalDriver($dir); }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->d->putFile($key, $localPath, $move); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { self::$reads++; $this->d->readRange($key, $start, $end, $sink); }
    public function readTo(string $key, string $localPath): void { self::$reads++; $this->d->readTo($key, $localPath); }
    public function size(string $key): ?int { return $this->d->size($key); }
    public function delete(string $key): void { $this->d->delete($key); }
    public function listKeys(string $prefix): array { return $this->d->listKeys($prefix); }
    public function listObjects(string $prefix): array { return $this->d->listObjects($prefix); }
    public function label(): string { return 's3://zz-bk'; }
}

echo "\nBackups and the stores\n" . str_repeat('=', 72) . "\n";
$conn = connectToDatabase();
$dbName = (string)$conn->query('SELECT DATABASE()')->fetchColumn();
if (getenv('FREEITSM_TEST_DATABASE') !== $dbName) {
    echo "\nSKIPPED: set FREEITSM_TEST_DATABASE to a database this may REPLACE.\n\n$pass passed, $fail failed\n";
    exit($fail ? 1 : 0);
}
$work = sys_get_temp_dir() . '/zz-sb-' . bin2hex(random_bytes(4));
mkdir($work);
$admin = (int)$conn->query('SELECT id FROM analysts ORDER BY id LIMIT 1')->fetchColumn();
$snap = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key LIKE 'backup\\_%' OR setting_key LIKE 'storage\\_%'")->fetchAll(PDO::FETCH_KEY_PAIR);
$firstRun = (int)$conn->query('SELECT COALESCE(MAX(id), 0) FROM backup_runs')->fetchColumn();
$rm = function (string $d) use (&$rm) {
    foreach (glob("$d/{,.}*", GLOB_BRACE) ?: [] as $f) {
        if (in_array(basename($f), ['.', '..'], true)) continue;
        is_dir($f) && !is_link($f) ? $rm($f) : @unlink($f);
    }
    @rmdir($d);
};

try {
    // Backups to a folder; tickets in "S3"; documents on the server folder.
    $conn->exec("DELETE FROM system_settings WHERE setting_key LIKE 'backup\\_%' OR setting_key LIKE 'storage\\_%'");
    BackupsService::$kdfOps = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    BackupsService::$kdfMem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    mkdir("$work/target");
    BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => "$work/target"], $admin);
    BackupsService::setPassphrase($conn, 'stores backup passphrase', 'stores backup passphrase', $admin);
    $target = backupTargetDriver(backupTargetConfig($conn));

    foreach (array_keys(STORAGE_STORES) as $s) StoreCache::$roots[$s] = "$work/local-$s";
    StoreCache::$roots['documents'] = "$work/app/uploads/documents";   // a store on its folder: where the backup walks (the app root)
    StoreCache::$factory = fn(array $cfg, string $store) => ($cfg['driver'] ?? 'local') === 's3'
        ? new ZzBkStoreS3("$work/s3-$store") : new LocalDriver((string)$cfg['root']);
    foreach (['endpoint' => 'http://zz.invalid', 'bucket' => 'zz', 'access_key_id' => 'k', 'secret' => encryptValue('s'), 'region' => 'us-east-1', 'prefix' => '', 'path_style' => '1'] as $k => $v) {
        storeSaveSetting($conn, "storage_s3_$k", $v);
    }
    storeSaveSetting($conn, 'storage_tickets_location', 's3');
    storeReset();
    $put = function (string $store, string $key, string $bytes) use ($conn) {
        $tmp = tempnam(sys_get_temp_dir(), 'zzb');
        file_put_contents($tmp, $bytes);
        storePutFile($conn, $store, $key, $tmp, true);
    };
    $put('tickets', '0/1/kept.pdf', 'ticket kept');
    $put('tickets', '0/1/deleted later.pdf', 'ticket deleted later');
    $put('documents', 'doc-kept.pdf', 'document kept');
    @mkdir("$work/local-tickets/0/1", 0777, true);
    file_put_contents("$work/local-tickets/0/1/stale.pdf", 'an old copy left in the folder');   // not the store any more

    $app = "$work/app";
    @mkdir($app, 0777, true);
    $runner = fn() => new BackupRunner($conn, $target, $app, fn() => null, ENCRYPTION_KEY_PATH);

    section('Backing up a store kept in S3');
    $b1 = $runner()->run('manual', $admin);
    ok('the backup succeeds', $b1['status'] === 'ok', (string)$b1['error']);
    $open = backupOpenSet($target, (string)$b1['set'], 'stores backup passphrase');
    $paths = array_map(fn($f) => $f['store'] . ':' . $f['path'], $open['manifest']['files']);
    sodium_memzero($open['keys']['secret']);
    ok('the S3 store\'s files are in it, as dir: entries (format unchanged)', in_array('dir:tickets/attachments:0/1/kept.pdf', $paths, true)
       && in_array('dir:tickets/attachments:0/1/deleted later.pdf', $paths, true), json_encode($paths));
    ok('a stale copy in the folder of a store kept in S3 is not', !in_array('dir:tickets/attachments:0/1/stale.pdf', $paths, true));
    ok('documents on the server folder are in it as before (dir:uploads, documents/...)', in_array('dir:uploads:documents/doc-kept.pdf', $paths, true));
    ZzBkStoreS3::$reads = 0;
    $b2 = $runner()->run('manual', $admin);
    ok('the next backup does not download unchanged files from S3 again', $b2['status'] === 'ok' && ZzBkStoreS3::$reads === 0, (string)ZzBkStoreS3::$reads);

    section('Rolling back');
    storeDelete($conn, 'tickets', '0/1/deleted later.pdf');
    $put('tickets', '0/2/added later.pdf', 'added after the backup');
    $put('documents', 'doc-added.pdf', 'document added after');
    storeSaveSetting($conn, 'storage_changes_location', 's3');   // a setting changed since: this install's, kept
    storeReset();
    backupMaintenanceStart($admin, (string)$b1['set']);
    $rb = new BackupRollback($conn, $target, (string)$b1['set'], 'stores backup passphrase', $admin, $app, ENCRYPTION_KEY_PATH, new LocalDriver("$work/files"), fn() => null);
    $rb->verifySchema = fn() => true;
    $rb->jobWaitSeconds = 5;
    $res = $rb->run();
    storeReset();
    ok('rollback: done', $res['state'] === 'done', json_encode($res));
    ok('a file deleted since is back - in S3, where the store is kept', is_file("$work/s3-tickets/0/1/deleted later.pdf")
       && !is_file("$work/local-tickets/0/1/deleted later.pdf"));
    ok('a file added since is gone from S3', !is_file("$work/s3-tickets/0/2/added later.pdf"));
    ok('a document added since is gone from the server folder', !is_file("$app/uploads/documents/doc-added.pdf") && is_file("$app/uploads/documents/doc-kept.pdf"));
    ok('the folder of a store kept in S3 is left alone', is_file("$work/local-tickets/0/1/stale.pdf"));
    ok('this install\'s storage settings are kept', storeLocation($conn, 'tickets') === 's3' && storeLocation($conn, 'changes') === 's3'
       && storeSetting($conn, 'storage_s3_bucket') === 'zz');

    section('No rollback while a store is moving');
    @mkdir("$work/local-warroom", 0777, true);
    file_put_contents("$work/local-warroom/w.txt", 'x');
    storeMoveStart($conn, 'warroom', 's3', $admin);
    backupMaintenanceStart($admin, (string)$b1['set']);
    $rb = new BackupRollback($conn, $target, (string)$b1['set'], 'stores backup passphrase', $admin, $app, ENCRYPTION_KEY_PATH, new LocalDriver("$work/files"), fn() => null);
    $rb->verifySchema = fn() => true;
    $res = $rb->run();
    ok('refused before anything changes', $res['state'] === 'failed' && $res['safety_set'] === null && str_contains((string)$res['error'], 'moving'), json_encode($res));
    $e = null;
    try { BackupsService::restoreStart($conn, (int)$b1['run_id'], 'stores backup passphrase', 'RESTORE', $admin); } catch (BackupsInputError $x) { $e = $x->getMessage(); }
    ok('...and the page refuses to start one', $e === 'err_storage_moving', (string)$e);
    storeMoveAction($conn, 'warroom', 'retry_failed', $admin);
    storeMoveEnd($conn, 'warroom', 'test');
} catch (Throwable $e) {
    ok('no unexpected error', false, get_class($e) . ': ' . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine());
} finally {
    try { backupMaintenanceEnd(['state' => 'abandoned']); } catch (Throwable $ignored) {}
    @unlink(backupMaintenanceLastFile());
    $conn->exec("DELETE FROM storage_migration_items WHERE store <> 'files'");
    $conn->prepare('DELETE FROM backup_runs WHERE id > ?')->execute([$firstRun]);
    $conn->exec("DELETE FROM system_settings WHERE setting_key LIKE 'backup\\_%' OR setting_key LIKE 'storage\\_%'");
    $i = $conn->prepare('INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)');
    foreach ($snap as $k => $v) $i->execute([$k, $v]);
    try { $conn->exec("DELETE FROM storage_object_hashes"); } catch (Throwable $ignored) {}
    StoreCache::$roots = [];
    StoreCache::$factory = null;
    storeReset();
    $rm($work);
}

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
