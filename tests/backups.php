<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * Backups (#286): storage listing, encryption, the database dump, the backup
 * run, pruning, verification and the command-line restore.
 *
 * Writes ZZ rows, a zz_backup_t table and (when allowed) a scratch database
 * <db>_zzrestore, all removed at the end. Needs FREEITSM_TEST_DATABASE set to the
 * database it may write to:
 *   FREEITSM_TEST_DATABASE=<db> php tests/backups.php
 */

$root = dirname(__DIR__);
require_once "$root/config.php";
require_once "$root/includes/functions.php";
require_once "$root/includes/storage_persistence.php";
require_once "$root/includes/storage/driver.php";
require_once "$root/includes/storage/s3_driver.php";
require_once "$root/includes/backup/crypto.php";
require_once "$root/includes/backup/dump.php";
require_once "$root/includes/backup/target.php";
require_once "$root/includes/services/backups.php";
require_once "$root/includes/job_registry.php";
require_once "$root/includes/encryption.php";
require_once "$root/includes/files/storage.php";
require_once "$root/includes/backup/runner.php";
require_once "$root/includes/backup/restore.php";
require_once "$root/includes/i18n.php";

$pass = 0; $fail = 0;
function ok(string $label, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; printf("  PASS %-70s\n", $label); }
    else       { $fail++; printf("  FAIL %-70s %s\n", $label, $detail); }
}
/** Files storage stand-in: a folder that can be switched off like an unreachable S3. */
final class ZzBkFakeS3 implements StorageDriver
{
    public bool $down = false;
    public int $reads = 0;
    private LocalDriver $d;
    public function __construct(string $dir) { $this->d = new LocalDriver($dir); }
    private function up(): void { if ($this->down) throw new StorageUnavailable('Storage could not be reached: test stand-in is down'); }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->up(); $this->d->putFile($key, $localPath, $move); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { $this->up(); $this->d->readRange($key, $start, $end, $sink); }
    public function readTo(string $key, string $localPath): void { $this->up(); $this->reads++; $this->d->readTo($key, $localPath); }
    public function size(string $key): ?int { $this->up(); return $this->d->size($key); }
    public function delete(string $key): void { $this->up(); $this->d->delete($key); }
    public function label(): string { return 'zz-fake-s3'; }
}
function section(string $t): void { echo "\n$t\n" . str_repeat('-', 72) . "\n"; }

echo "\nBackups\n" . str_repeat('=', 72) . "\n";

// ── Pure checks (no database) ──
section('S3 list response parsing');
$xml = '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
     . '<Name>b</Name><Prefix>p/</Prefix><KeyCount>2</KeyCount><IsTruncated>true</IsTruncated>'
     . '<NextContinuationToken>t+1/=</NextContinuationToken>'
     . '<Contents><Key>p/backup/a&amp;b.txt</Key><LastModified>2026-11-10T08:00:00.000Z</LastModified><Size>3</Size></Contents>'
     . '<Contents><Key>p/backup/c.txt</Key><Size>4</Size></Contents></ListBucketResult>';
$r = s3ParseListObjects($xml);
ok('keys are read (entities decoded)', $r['keys'] === ['p/backup/a&b.txt', 'p/backup/c.txt'], json_encode($r));
ok('continuation token when truncated', $r['next'] === 't+1/=');
ok('sizes and dates are read', ($r['objects']['p/backup/a&b.txt']['size'] ?? null) === 3
   && ($r['objects']['p/backup/a&b.txt']['mtime'] ?? null) === strtotime('2026-11-10T08:00:00Z'), json_encode($r['objects'] ?? null));
$r = s3ParseListObjects(str_replace('<IsTruncated>true</IsTruncated>', '<IsTruncated>false</IsTruncated>', $xml));
ok('no continuation when not truncated', $r['next'] === null);
$r = s3ParseListObjects('<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>');
ok('an empty listing is an empty list', $r['keys'] === [] && $r['next'] === null);
$threw = null;
try { s3ParseListObjects('<html>proxy error</html'); } catch (Throwable $e) { $threw = $e; }
ok('a response that is not a listing fails (never an empty list)', $threw instanceof StorageUnavailable, $threw ? get_class($threw) : 'returned');

section('Persistence directories');
$rels = array_column(storagePersistenceDirectories(), 'rel');
ok('label fonts are covered', in_array('system/uploads/label-fonts', $rels, true));
ok('form images are covered', in_array('forms/images', $rels, true));

section('Encryption');
$fast = [SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE];
ok('sodium is available', backupSodiumAvailable());
$kr = backupNewKeyring('correct horse battery', ...$fast);
ok('a keyring has a public key and a 32-byte pool name key', strlen($kr['pool_name_key']) === 32 && $kr['public'] !== '');
$json = json_encode($kr['keyring']);
ok('the published keyring holds no secret in the clear', !str_contains($json, base64_encode($kr['pool_name_key'])));
$keys = backupUnlockKeyring($kr['keyring'], 'correct horse battery');
ok('the passphrase unlocks the keyring', base64_encode($keys['public']) === $kr['public'] && $keys['pool_name_key'] === $kr['pool_name_key']);
$threw = null;
try { backupUnlockKeyring($kr['keyring'], 'wrong horse battery'); } catch (Throwable $e) { $threw = $e; }
ok('a wrong passphrase is refused', $threw instanceof BackupWrongPassphrase, $threw ? get_class($threw) : 'unlocked');
$re = backupRekeyKeyring($kr['keyring'], 'correct horse battery', 'a brand new passphrase');
$k2 = backupUnlockKeyring($re, 'a brand new passphrase');
ok('rekey: the new passphrase opens the same keys', $k2['public'] === $keys['public'] && $k2['secret'] === $keys['secret'] && $k2['pool_name_key'] === $keys['pool_name_key']);
$threw = null;
try { backupUnlockKeyring($re, 'correct horse battery'); } catch (Throwable $e) { $threw = $e; }
ok('rekey: the old passphrase no longer opens it', $threw instanceof BackupWrongPassphrase);
$threw = null;
try { backupRekeyKeyring($kr['keyring'], 'not the passphrase', 'whatever else'); } catch (Throwable $e) { $threw = $e; }
ok('rekey with a wrong old passphrase is refused', $threw instanceof BackupWrongPassphrase);

$dk = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
$sealed = backupSealKey($dk, $keys['public']);
ok('a sealed key opens with the keypair', backupOpenKey($sealed, $keys['public'], $keys['secret']) === $dk);
$threw = null;
try { backupOpenKey(substr($sealed, 0, -1) . chr(ord(substr($sealed, -1)) ^ 1), $keys['public'], $keys['secret']); } catch (Throwable $e) { $threw = $e; }
ok('a damaged sealed key is refused', $threw instanceof BackupCorrupt);

$tmpd = sys_get_temp_dir() . '/zz-bkc-' . bin2hex(random_bytes(4));
mkdir($tmpd);
try {
    foreach ([0, 1, 65536, 65537, 204800] as $n) {
        $plain = $n ? random_bytes($n) : '';
        file_put_contents("$tmpd/p", $plain);
        $written = backupEncryptFile("$tmpd/p", "$tmpd/e", $dk);
        $sha = backupDecryptFile("$tmpd/e", "$tmpd/d", $dk);
        ok("file of $n bytes: round trip", file_get_contents("$tmpd/d") === $plain && $sha === hash('sha256', $plain));
        ok("file of $n bytes: size is predictable", filesize("$tmpd/e") === backupEncryptedSize($n) && $written === backupEncryptedSize($n),
           filesize("$tmpd/e") . ' / ' . $written . ' vs ' . backupEncryptedSize($n));
        if ($n > 1000) ok("file of $n bytes: no plaintext in the output", !str_contains(file_get_contents("$tmpd/e"), substr($plain, 500, 64)));
    }
    file_put_contents("$tmpd/p", random_bytes(204800));
    backupEncryptFile("$tmpd/p", "$tmpd/e", $dk);
    $enc = file_get_contents("$tmpd/e");
    $mid = intdiv(strlen($enc), 2);
    file_put_contents("$tmpd/x", substr($enc, 0, $mid) . chr(ord($enc[$mid]) ^ 1) . substr($enc, $mid + 1));
    $threw = null;
    try { backupDecryptFile("$tmpd/x", "$tmpd/d", $dk); } catch (Throwable $e) { $threw = $e; }
    ok('a flipped byte is detected', $threw instanceof BackupCorrupt, $threw ? get_class($threw) : 'decrypted');
    // 204800 = 3 full chunks + 8192: drop the short last chunk (8192 + 17 bytes).
    file_put_contents("$tmpd/x", substr($enc, 0, strlen($enc) - (8192 + 17)));
    $threw = null;
    try { backupDecryptFile("$tmpd/x", "$tmpd/d", $dk); } catch (Throwable $e) { $threw = $e; }
    ok('a missing last chunk is detected', $threw instanceof BackupCorrupt, $threw ? get_class($threw) : 'decrypted');
    $threw = null;
    try { backupDecryptFile("$tmpd/e", "$tmpd/d", random_bytes(32)); } catch (Throwable $e) { $threw = $e; }
    ok('the wrong key is detected', $threw instanceof BackupCorrupt);
    ok('strings round trip', backupDecryptString(backupEncryptString('{"a":1}', $dk), $dk) === '{"a":1}');
    ok('pool names are stable for one key', backupPoolName($kr['pool_name_key'], str_repeat('a', 64)) === backupPoolName($kr['pool_name_key'], str_repeat('a', 64)));
    ok('pool names differ under another key', backupPoolName($kr['pool_name_key'], str_repeat('a', 64)) !== backupPoolName(random_bytes(32), str_repeat('a', 64)));
    ok('a pool name does not reveal the hash', !str_contains(backupPoolName($kr['pool_name_key'], str_repeat('a', 64)), str_repeat('a', 16)));
} finally {
    foreach (glob("$tmpd/*") as $f) @unlink($f);
    @rmdir($tmpd);
}

// ── Database checks ──
$conn = connectToDatabase();
$dbName = (string)$conn->query('SELECT DATABASE()')->fetchColumn();
if (getenv('FREEITSM_TEST_DATABASE') !== $dbName) {
    echo "\nSKIPPED database checks: set FREEITSM_TEST_DATABASE to the database this may write to (this one is $dbName).\n";
    echo "\n$pass passed, $fail failed\n";
    exit($fail ? 1 : 0);
}
$restoreDb = $dbName . '_zzrestore';
/** A connection to the scratch restore database, created empty; null when this login may not create databases. */
function zzRestoreConn(PDO $conn, string $name): ?PDO {
    try {
        $conn->exec("DROP DATABASE IF EXISTS `$name`");
        $conn->exec("CREATE DATABASE `$name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    } catch (PDOException $e) {
        return null;
    }
    $c = new PDO('mysql:host=' . DB_SERVER . ";dbname=$name;charset=utf8mb4", DB_USERNAME, DB_PASSWORD, dbConnectionOptions());
    $c->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $c;
}
function zzTableCounts(PDO $c): array {
    $out = [];
    foreach ($c->query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")->fetchAll(PDO::FETCH_NUM) as $r) {
        $out[$r[0]] = (int)$c->query('SELECT COUNT(*) FROM `' . $r[0] . '`')->fetchColumn();
    }
    ksort($out);
    return $out;
}
$work = sys_get_temp_dir() . '/zz-bk-' . bin2hex(random_bytes(4));
mkdir($work);
$cleanup = [];   // closures run at the end, newest first

try {
    section('Database dump and replay');
    $conn->exec('DROP TABLE IF EXISTS zz_backup_t');
    $conn->exec('CREATE TABLE zz_backup_t (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, s VARCHAR(50) NULL, b LONGBLOB NULL,
                 n DECIMAL(10,2) NOT NULL DEFAULT 0, g DECIMAL(12,2) AS (n * 2) STORED, t DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $cleanup[] = fn() => $conn->exec('DROP TABLE IF EXISTS zz_backup_t');
    $big = random_bytes(3 * 1024 * 1024);
    $ins = $conn->prepare('INSERT INTO zz_backup_t (s, b, n, t) VALUES (?, ?, ?, ?)');
    $ins->execute([null, null, '0.00', null]);
    $ins->execute(["O'Brien \\ \n \"q\"", '', '12.34', '2026-11-12 08:30:00']);
    $ins->bindValue(1, 'big'); $ins->bindValue(2, $big, PDO::PARAM_LOB); $ins->bindValue(3, '-5.50'); $ins->bindValue(4, null);
    $ins->execute();
    $ins->execute(['Žluťoučký 🚀', "\x00\x01\xff", '1.00', '1999-12-31 23:59:59']);

    $dump = "$work/db.dump";
    $conn->beginTransaction();
    $info = backupDumpDatabase($conn, $dump, 1024 * 1024);
    $conn->commit();
    ok('the dump counts every table', ($info['tables']['zz_backup_t'] ?? null) === 4 && count($info['tables']) === count(zzTableCounts($conn)),
       json_encode($info['tables']['zz_backup_t'] ?? null));
    ok('the dump is compressed (smaller than the big row)', filesize($dump) > 3 * 1024 * 1024 && filesize($dump) < 4 * 1024 * 1024, (string)filesize($dump));
    $threw = null;
    try { backupDumpDatabase($conn, "$work/x.dump"); } catch (Throwable $e) { $threw = $e; }
    ok('dumping outside a transaction is refused (no consistent snapshot)', $threw instanceof LogicException, $threw ? get_class($threw) : 'dumped');

    $rc = zzRestoreConn($conn, $restoreDb);
    if (!$rc) {
        echo "  SKIP replay (this login may not create the scratch database $restoreDb)\n";
    } else {
        $cleanup[] = fn() => $conn->exec("DROP DATABASE IF EXISTS `$restoreDb`");
        $n = backupReplayDump($rc, $dump);
        ok('the dump replays', $n > 10, (string)$n);
        ok('every table comes back with the same row count', zzTableCounts($rc) === zzTableCounts($conn));
        $sum = "SELECT GROUP_CONCAT(SHA2(CONCAT_WS('|', id, IFNULL(s,'<null>'), IFNULL(HEX(b),'<null>'), n, g, IFNULL(t,'<null>')), 256) ORDER BY id) FROM zz_backup_t";
        ok('every value comes back the same (NULLs, quotes, binary, unicode, dates)', $rc->query($sum)->fetchColumn() === $conn->query($sum)->fetchColumn());
        ok('the 3 MiB row comes back whole', hash('sha256', (string)$rc->query("SELECT b FROM zz_backup_t WHERE s = 'big'")->fetchColumn()) === hash('sha256', $big));
        ok('auto increment continues after the restored rows',
           (int)$rc->query("SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'zz_backup_t'")->fetchColumn() >= 5);
        file_put_contents("$work/cut.dump", substr(file_get_contents($dump), 0, 2000));
        $threw = null;
        try { backupReplayDump($rc, "$work/cut.dump"); } catch (Throwable $e) { $threw = $e; }
        ok('a truncated dump fails rather than restoring part of the data silently', $threw instanceof RuntimeException, $threw ? get_class($threw) : 'replayed');
    }

    section('Settings: target, passphrase, schedule');
    // Every backup setting and the job's schedule row are put back at the end.
    $snap = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key LIKE 'backup\\_%'")->fetchAll(PDO::FETCH_KEY_PAIR);
    $schedRow = $conn->query("SELECT * FROM job_schedules WHERE job_key = 'backup'")->fetch(PDO::FETCH_ASSOC) ?: null;
    $cleanup[] = function () use ($conn, $snap, $schedRow) {
        $conn->exec("DELETE FROM system_settings WHERE setting_key LIKE 'backup\\_%'");
        $ins = $conn->prepare('INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)');
        foreach ($snap as $k => $v) $ins->execute([$k, $v]);
        if ($schedRow) {
            $conn->prepare('UPDATE job_schedules SET mode = ?, interval_minutes = ?, at_time = ?, next_due_at = ? WHERE job_key = ?')
                 ->execute([$schedRow['mode'], $schedRow['interval_minutes'], $schedRow['at_time'], $schedRow['next_due_at'], 'backup']);
        } else {
            $conn->exec("DELETE FROM job_schedules WHERE job_key = 'backup'");
        }
    };
    $conn->exec("DELETE FROM system_settings WHERE setting_key LIKE 'backup\\_%'");
    BackupsService::$kdfOps = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    BackupsService::$kdfMem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    $admin = (int)$conn->query('SELECT id FROM analysts ORDER BY id LIMIT 1')->fetchColumn();

    ok('the backup_runs table exists', (bool)$conn->query("SHOW TABLES LIKE 'backup_runs'")->fetchColumn());
    $d = BackupsService::describe($conn);
    ok('a fresh install has no target, no passphrase, schedule off', $d['target'] === null && !$d['has_passphrase'] && $d['schedule']['mode'] === 'off' && $d['keep'] === 7);
    ok('a fresh install does not need the backup job', jobRegistry()['backup']['needed']($conn) === false);

    $folder = "$work/target";
    mkdir($folder);
    $t = BackupsService::test(['type' => 'folder', 'folder' => $folder]);
    ok('test: a writable folder passes', $t['ok'] === true, json_encode($t));
    $t = BackupsService::test(['type' => 'folder', 'folder' => "$work/does-not-exist"]);
    ok('test: a missing folder fails', $t['ok'] === false && $t['step'] !== null);
    ok('test: nothing is left behind', (new LocalDriver("$folder/backup"))->listKeys('_freeitsm_test/') === []);

    $err = fn(callable $f) => (function () use ($f) { try { $f(); return null; } catch (BackupsInputError $e) { return $e->getMessage(); } })();
    ok('save: a relative folder is refused', $err(fn() => BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => 'backups'], $admin)) === 'err_folder_absolute');
    ok('save: a folder inside the application is refused',
       $err(fn() => BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => dirname(__DIR__) . '/uploads'], $admin)) === 'err_folder_inside_app');
    ok('save: a folder that fails the test is refused', $err(fn() => BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => "$work/nope"], $admin)) === 'err_target_test');
    BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => $folder], $admin);
    ok('save: a good folder is saved', (backupTargetConfig($conn)['folder'] ?? null) === $folder);

    ok('passphrase: too short is refused', $err(fn() => BackupsService::setPassphrase($conn, 'short', 'short', $admin)) === 'err_passphrase_short');
    ok('passphrase: a mismatch is refused', $err(fn() => BackupsService::setPassphrase($conn, 'long enough passphrase', 'long enough passphrasE', $admin)) === 'err_passphrase_mismatch');
    BackupsService::setPassphrase($conn, 'long enough passphrase', 'long enough passphrase', $admin);
    $kr = json_decode((string)backupSetting($conn, 'backup_keyring'), true);
    ok('passphrase: the saved keyring opens with it', is_array($kr) && backupUnlockKeyring($kr, 'long enough passphrase')['public'] !== '');
    ok('passphrase: the keyring is written to the target', json_decode((string)@file_get_contents("$folder/backup/keyring.json"), true) == $kr);
    ok('passphrase: an install id is made', preg_match('/^[0-9a-f]{32}$/', backupSetting($conn, 'backup_install_id')) === 1);
    $poolSecret = (string)$conn->query("SELECT setting_value FROM system_settings WHERE setting_key = 'backup_pool_name_secret'")->fetchColumn();
    ok('passphrase: the pool name key is stored encrypted', str_starts_with($poolSecret, 'ENC:'));
    ok('passphrase: it cannot be set twice', $err(fn() => BackupsService::setPassphrase($conn, 'another long passphrase', 'another long passphrase', $admin)) === 'err_passphrase_exists');
    ok('passphrase change: a wrong current passphrase is refused',
       $err(fn() => BackupsService::changePassphrase($conn, 'not the passphrase!', 'a new long passphrase', 'a new long passphrase', $admin)) === 'err_passphrase_wrong');
    $pub = backupSetting($conn, 'backup_public_key');
    BackupsService::changePassphrase($conn, 'long enough passphrase', 'a new long passphrase', 'a new long passphrase', $admin);
    $kr2 = json_decode((string)backupSetting($conn, 'backup_keyring'), true);
    ok('passphrase change: the new one opens the same keys', base64_encode(backupUnlockKeyring($kr2, 'a new long passphrase')['public']) === $pub);
    ok('passphrase change: the target keyring is replaced', json_decode((string)file_get_contents("$folder/backup/keyring.json"), true) == $kr2);

    ok('schedule: weekly needs a day', $err(fn() => BackupsService::saveSchedule($conn, 'weekly', 0, '02:00', 7, $admin)) === 'err_schedule_day');
    ok('schedule: a bad time is refused', $err(fn() => BackupsService::saveSchedule($conn, 'daily', null, '25:00', 7, $admin)) === 'err_schedule_time');
    ok('schedule: keep 0 is refused', $err(fn() => BackupsService::saveSchedule($conn, 'daily', null, '02:00', 0, $admin)) === 'err_keep');
    ok('schedule: keep 366 is refused', $err(fn() => BackupsService::saveSchedule($conn, 'daily', null, '02:00', 366, $admin)) === 'err_keep');
    BackupsService::saveSchedule($conn, 'daily', null, '02:30', 5, $admin);
    $row = $conn->query("SELECT mode, at_time FROM job_schedules WHERE job_key = 'backup'")->fetch(PDO::FETCH_ASSOC);
    ok('schedule: daily sets the job to run daily at that time', $row && $row['mode'] === 'daily' && substr((string)$row['at_time'], 0, 5) === '02:30', json_encode($row));
    ok('schedule: daily with a target and passphrase needs the job', jobRegistry()['backup']['needed']($conn) === true);
    $today = (int)date('N');
    BackupsService::saveSchedule($conn, 'weekly', $today, '02:30', 5, $admin);
    ok('schedule: weekly is needed on its day', jobRegistry()['backup']['needed']($conn) === true);
    BackupsService::saveSchedule($conn, 'weekly', $today % 7 + 1, '02:30', 5, $admin);
    ok('schedule: weekly is not needed on another day', jobRegistry()['backup']['needed']($conn) === false);
    BackupsService::saveSchedule($conn, 'off', null, null, 5, $admin);
    ok('schedule: off is not needed and the job is off',
       jobRegistry()['backup']['needed']($conn) === false && $conn->query("SELECT mode FROM job_schedules WHERE job_key = 'backup'")->fetchColumn() === 'off');

    $t = BackupsService::test(['type' => 's3', 's3' => ['endpoint' => 'http://169.254.169.254', 'bucket' => 'b', 'access_key_id' => 'k', 'secret' => 'x']]);
    ok('test: a link-local (cloud metadata) endpoint is refused', $t['ok'] === false && $t['step'] === 'connect');
    $s3ep = getenv('FREEITSM_TEST_S3_ENDPOINT') ?: '';
    if ($s3ep !== '') {
        $s3in = ['endpoint' => $s3ep, 'bucket' => getenv('FREEITSM_TEST_S3_BUCKET'), 'access_key_id' => getenv('FREEITSM_TEST_S3_KEY'),
                 'secret' => getenv('FREEITSM_TEST_S3_SECRET'), 'prefix' => 'zz-bk-' . bin2hex(random_bytes(3)), 'path_style' => true];
        BackupsService::saveTarget($conn, ['type' => 's3', 's3' => $s3in], $admin);
        $d = BackupsService::describe($conn);
        ok('S3 target: saved, and describe() masks the secret', $d['target']['type'] === 's3' && $d['target']['s3']['secret'] !== $s3in['secret']
           && str_starts_with((string)$d['target']['s3']['secret'], '****'), json_encode($d['target']));
        ok('S3 target: the secret is stored encrypted',
           str_starts_with((string)$conn->query("SELECT setting_value FROM system_settings WHERE setting_key = 'backup_s3_secret'")->fetchColumn(), 'ENC:'));
        ok('S3 target: the keyring is written there too', backupTargetDriver(backupTargetConfig($conn))->size('keyring.json') !== null);
        BackupsService::saveTarget($conn, ['type' => 's3', 's3' => ['secret' => $d['target']['s3']['secret']] + $s3in], $admin);
        ok('S3 target: saving the masked secret keeps the saved one', backupTargetConfig($conn)['secret'] === $s3in['secret']);
        $sd = backupTargetDriver(backupTargetConfig($conn));
        foreach ($sd->listKeys('') as $k) $sd->delete($k);
    } else {
        echo "  SKIP S3 target checks (no S3 test endpoint)\n";
    }
    BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => $folder], $admin);
    ok('describe() never contains the pool name key', !str_contains(json_encode(BackupsService::describe($conn)), bin2hex(backupPoolNameKey($conn))));

    section('The backup run');
    // Files on a stand-in "S3" (a folder that can be switched off), a ZZ file in an upload
    // folder, and a folder target. The passphrase and target come from the section above.
    $s3dir = "$work/fake-s3";
    mkdir($s3dir);
    $fake = new ZzBkFakeS3($s3dir);
    filesStorageReset();
    FilesStorageCache::$drivers['active'] = $fake;
    $appRoot = dirname(__DIR__);
    $upDir = "$appRoot/uploads/zz-backup-test-" . bin2hex(random_bytes(3));
    mkdir($upDir, 0777, true);
    $cleanup[] = function () use ($upDir) { foreach (glob("$upDir/*") as $f) @unlink($f); @rmdir($upDir); };
    $marker = 'ZZ-BACKUP-PLAINTEXT-MARKER-' . bin2hex(random_bytes(8));
    file_put_contents("$upDir/note.txt", "$marker in a dir file");

    $conn->prepare("INSERT INTO files_folders (name, created_by, created_datetime) VALUES ('ZZ backup test', ?, UTC_TIMESTAMP())")->execute([$admin]);
    $zzFolder = (int)$conn->lastInsertId();
    $cleanup[] = fn() => $conn->prepare('DELETE FROM files_folders WHERE id = ?')->execute([$zzFolder]);
    $mkFile = function (string $bytes) use ($conn, $zzFolder, $admin, $fake, &$cleanup): array {
        $key = gmdate('Y/m/d/') . bin2hex(random_bytes(16)) . '.bin';
        $conn->prepare("INSERT INTO files_items (folder_id, name, size_bytes, mime_type, created_by, created_datetime) VALUES (?, ?, ?, 'text/plain', ?, UTC_TIMESTAMP())")
             ->execute([$zzFolder, 'ZZ ' . bin2hex(random_bytes(3)) . '.txt', strlen($bytes), $admin]);
        $item = (int)$conn->lastInsertId();
        $conn->prepare("INSERT INTO files_versions (item_id, version_no, storage_path, size_bytes, mime_type, sha256, uploaded_by, uploaded_datetime) VALUES (?, 1, ?, ?, 'text/plain', ?, ?, UTC_TIMESTAMP())")
             ->execute([$item, $key, strlen($bytes), hash('sha256', $bytes), $admin]);
        $cleanup[] = fn() => $conn->prepare('DELETE FROM files_items WHERE id = ?')->execute([$item]);
        $tmp = tempnam(sys_get_temp_dir(), 'zzf');
        file_put_contents($tmp, $bytes);
        $fake->putFile($key, $tmp, true);
        return ['item' => $item, 'key' => $key, 'bytes' => $bytes];
    };
    $f1 = $mkFile("$marker in Files one");
    $f2 = $mkFile(random_bytes(150000));

    $target = backupTargetDriver(backupTargetConfig($conn));
    $mails = [];
    $mailer = function (string $subject, string $body) use (&$mails) { $mails[] = [$subject, $body]; };
    $runner = new BackupRunner($conn, $target, $appRoot, $mailer);

    $conn->beginTransaction();
    $threw = null;
    try { $runner->run('manual', $admin); } catch (Throwable $e) { $threw = $e; }
    $conn->rollBack();
    ok('a run on a connection already in a transaction is refused', $threw instanceof LogicException, $threw ? get_class($threw) : 'ran');

    $r1 = $runner->run('manual', $admin);
    ok('first run: ok', $r1['status'] === 'ok', json_encode($r1));
    $set1 = (string)$r1['set'];
    ok('first run: the set is complete (done.json)', $target->size("sets/$set1/done.json") !== null);
    $refs = array_values(array_filter(explode("\n", (string)@file_get_contents("$folder/backup/sets/$set1/refs.txt"))));
    ok('first run: refs.txt lists every pooled file once', $r1['files_total'] >= 3 && count($refs) === count(array_unique($refs)) && count($refs) <= $r1['files_total'],
       count($refs) . ' / ' . $r1['files_total']);
    ok('first run: every distinct file was uploaded', $r1['files_new'] === count($refs), $r1['files_new'] . ' vs ' . count($refs));
    $row = $conn->query('SELECT * FROM backup_runs WHERE id = ' . (int)$r1['run_id'])->fetch(PDO::FETCH_ASSOC);
    ok('first run: the run row says ok, with sizes', $row && $row['status'] === 'ok' && $row['set_name'] === $set1 && (int)$row['files_new'] === $r1['files_new']
       && (int)$row['started_by'] === $admin && $row['finished_at'] !== null && (int)$row['db_bytes'] > 0);
    $cleanup[] = fn() => $conn->exec('DELETE FROM backup_runs WHERE id >= ' . (int)$r1['run_id']);
    $leak = false;
    foreach ((new LocalDriver("$folder/backup"))->listKeys('') as $k) {
        if (str_contains((string)file_get_contents("$folder/backup/$k"), $marker)) $leak = $k;
    }
    ok('nothing on the target contains a file\'s plaintext', $leak === false, (string)$leak);
    $open = backupOpenSet($target, $set1, 'a new long passphrase');
    $paths = array_map(fn($f) => $f['store'] . ':' . $f['path'], $open['manifest']['files']);
    ok('the manifest lists the Files key', in_array('files:' . $f1['key'], $paths, true));
    ok('the manifest lists the upload folder file', in_array('dir:uploads:' . basename($upDir) . '/note.txt', $paths, true), implode(', ', array_slice($paths, 0, 8)));
    ok('the manifest skips the Files storage folder in the folder walk', !array_filter($paths, fn($p) => str_starts_with($p, 'dir:uploads:files/')));
    ok('the manifest carries this install and the table counts',
       $open['manifest']['install_id'] === backupSetting($conn, 'backup_install_id') && ($open['manifest']['tables']['backup_runs'] ?? null) !== null);

    $r2 = $runner->run('manual', $admin);
    ok('second run: ok and nothing new uploaded', $r2['status'] === 'ok' && $r2['files_new'] === 0, json_encode($r2));
    $fake->reads = 0;
    $r2b = $runner->run('manual', $admin);
    ok('Files already in the backup are not downloaded again', $r2b['status'] === 'ok' && $fake->reads === 0, 'reads: ' . $fake->reads);
    file_put_contents("$upDir/second.txt", 'another file ' . bin2hex(random_bytes(8)));
    $r3 = $runner->run('manual', $admin);
    ok('a new file: exactly one upload', $r3['status'] === 'ok' && $r3['files_new'] === 1, json_encode($r3));

    // A crashed upload left a short pool object: it must be uploaded again, not reused.
    $name = backupPoolName(backupPoolNameKey($conn), hash('sha256', $f2['bytes']));
    $p = "$folder/backup/pool/$name";
    file_put_contents($p, substr((string)file_get_contents($p), 0, 1000));
    $r4 = $runner->run('manual', $admin);
    ok('a truncated pool object is uploaded again', $r4['status'] === 'ok' && $r4['files_new'] === 1 && filesize($p) === backupEncryptedSize(150000), json_encode($r4));
    file_put_contents("$p.key", substr((string)file_get_contents("$p.key"), 0, 10));
    $r4b = $runner->run('manual', $admin);
    ok('a truncated sealed key is uploaded again', $r4b['status'] === 'ok' && $r4b['files_new'] === 1
       && filesize("$p.key") === SODIUM_CRYPTO_BOX_SEALBYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, json_encode($r4b));

    // Files storage down: the run fails, says so, emails, and prunes nothing.
    $setsBefore = count(array_unique(array_map(fn($k) => explode('/', $k)[1], $target->listKeys('sets/'))));
    $f4 = $mkFile('needs a download ' . bin2hex(random_bytes(4)));
    $fake->down = true;
    $mails = [];
    $r5 = $runner->run('scheduled', null);
    $fake->down = false;
    ok('Files storage down: the run fails', $r5['status'] === 'failed', json_encode($r5));
    ok('Files storage down: the error names Files', str_contains(strtolower((string)$r5['error']), 'files'), (string)$r5['error']);
    ok('Files storage down: administrators are emailed once', count($mails) === 1);
    ok('Files storage down: the failed set is not complete', $r5['set'] === null || $target->size('sets/' . $r5['set'] . '/done.json') === null);
    $setsAfter = array_unique(array_map(fn($k) => explode('/', $k)[1], $target->listKeys('sets/')));
    ok('Files storage down: no complete set was pruned', count($setsAfter) >= $setsBefore);

    // A Files version deleted while the backup runs: recorded, warned, not fatal.
    $f3 = $mkFile('short-lived ' . bin2hex(random_bytes(4)));
    $runner->afterInventory = function () use ($conn, $fake, $f3) {
        $conn->prepare('DELETE FROM files_items WHERE id = ?')->execute([$f3['item']]);
        $fake->delete($f3['key']);
    };
    $r6 = $runner->run('manual', $admin);
    $runner->afterInventory = null;
    ok('a Files version deleted mid-run: ok with a warning', $r6['status'] === 'ok' && (string)$r6['warning'] !== '', json_encode($r6));
    $m6 = backupOpenSet($target, $r6['set'], 'a new long passphrase')['manifest']['files'];
    $e6 = array_values(array_filter($m6, fn($f) => $f['path'] === $f3['key']));
    ok('...and the manifest records it as missing', $e6 && ($e6[0]['missing'] ?? '') !== '');
    $f5 = $mkFile('never backed up ' . bin2hex(random_bytes(4)));
    $fake->delete($f5['key']);
    $r7 = $runner->run('manual', $admin);
    ok('a Files version missing while its row still exists fails the run', $r7['status'] === 'failed', json_encode($r7));
    $conn->prepare('DELETE FROM files_items WHERE id = ?')->execute([$f5['item']]);
    $tmpf = tempnam(sys_get_temp_dir(), 'zzf');

    // An upload-folder file deleted while the backup runs: recorded, warned, not fatal.
    file_put_contents("$upDir/vanish.txt", 'gone soon ' . bin2hex(random_bytes(4)));
    $runner->afterInventory = function () use ($upDir) { @unlink("$upDir/vanish.txt"); };
    $r7b = $runner->run('manual', $admin);
    $runner->afterInventory = null;
    ok('an upload-folder file deleted mid-run: ok with a warning', $r7b['status'] === 'ok' && str_contains((string)$r7b['warning'], 'vanish.txt'), json_encode($r7b));

    // Two more good runs without second.txt, so the oldest sets hold the only reference to it.
    unlink("$upDir/second.txt");
    $r8 = $runner->run('manual', $admin);
    $r9 = $runner->run('manual', $admin);
    ok('two more runs: ok', $r8['status'] === 'ok' && $r9['status'] === 'ok');

    section('Pruning');
    $sets = function () use ($target): array {
        $s = [];
        foreach ($target->listKeys('sets/') as $k) if (str_ends_with($k, '/done.json')) $s[] = explode('/', $k)[1];
        sort($s);
        return $s;
    };
    $complete = $sets();
    ok('there are several complete sets', count($complete) >= 4, (string)count($complete));
    // Another install's set on the same target: never pruned, its pool objects kept.
    $other = '19990101T000000Z';
    foreach (['done.json' => json_encode(['format' => 1, 'install_id' => str_repeat('f', 32)]), 'owner.json' => json_encode(['install_id' => str_repeat('f', 32)]),
              'refs.txt' => "$name\n"] as $k => $v) {
        file_put_contents($tmpf, $v);
        $target->putFile("sets/$other/$k", $tmpf);
    }
    $myId = backupSetting($conn, 'backup_install_id');
    $orphan = 'pool/' . str_repeat('0', 64);
    file_put_contents($tmpf, 'orphan');
    $target->putFile($orphan, $tmpf);
    $mkIncomplete = function (string $name, string $owner, int $startedAgo) use ($target, $tmpf) {
        file_put_contents($tmpf, json_encode(['install_id' => $owner, 'started_at' => gmdate('c', time() - $startedAgo)]));
        $target->putFile("sets/$name/owner.json", $tmpf);
        file_put_contents($tmpf, 'x');
        $target->putFile("sets/$name/db.bin", $tmpf);
    };
    $mkIncomplete('20000101T000000Z', $myId, 3 * 86400);          // ours, abandoned long ago
    $mkIncomplete('20000101T000001Z', $myId, 60);                  // ours (or a clone's), still being written
    $mkIncomplete('20000101T000002Z', str_repeat('e', 32), 60);    // another install's, still being written
    $r0 = $runner->prune(99, $myId);
    ok('a fresh unreferenced pool object is kept (grace period)', $target->size($orphan) !== null, json_encode($r0));
    ok('another install writing a backup does not stop the clean-up', $r0['gc_skipped'] === false, json_encode($r0));
    ok('an abandoned incomplete set of ours is removed', !$target->listKeys('sets/20000101T000000Z/'));
    ok('a recent incomplete set of ours is left alone', (bool)$target->listKeys('sets/20000101T000001Z/'));
    ok('another install\'s incomplete set is left alone', (bool)$target->listKeys('sets/20000101T000002Z/'));
    foreach (['20000101T000001Z', '20000101T000002Z'] as $n) foreach ($target->listKeys("sets/$n/") as $k) $target->delete($k);
    $runner->gcGraceSeconds = 0;
    $r = $runner->prune(2, $myId);
    $left = $sets();
    ok('without the grace period the orphan goes', $target->size($orphan) === null);
    ok('prune keeps the newest N of this install', array_values(array_diff($left, [$other])) === array_slice($complete, -2), json_encode($left));
    ok('prune leaves another install\'s set alone', in_array($other, $left, true));
    ok('prune removed the older sets', $r['sets_removed'] >= count($complete) - 2, json_encode($r));
    $union = [];
    foreach ($left as $s) foreach (array_filter(explode("\n", (string)file_get_contents("$folder/backup/sets/$s/refs.txt"))) as $n) $union[$n] = true;
    $pool = array_unique(array_map(fn($k) => preg_replace('/\.key$/', '', substr($k, 5)), $target->listKeys('pool/')));
    ok('the pool holds exactly what remaining sets reference', !array_diff($pool, array_keys($union)) && !array_diff(array_keys($union), $pool),
       count($pool) . ' vs ' . count($union));
    ok('the pool lost something (objects only old sets used)', $r['pool_removed'] > 0, json_encode($r));

    // An unreadable refs.txt: nothing is deleted from the pool.
    $victim = $left[0] === $other ? $left[1] : $left[0];
    $rp = "$folder/backup/sets/$victim/refs.txt";
    rename($rp, "$rp.bak");
    mkdir($rp);
    file_put_contents("$rp/x", 'x');
    $before = $target->listKeys('pool/');
    $r = $runner->prune(2, backupSetting($conn, 'backup_install_id'));
    ok('an unreadable refs.txt skips the pool clean-up', $r['gc_skipped'] === true && $target->listKeys('pool/') === $before, json_encode($r));
    unlink("$rp/x"); rmdir($rp); rename("$rp.bak", $rp);


    section('Verify a backup');
    $latest = $sets();
    $good = end($latest) === $other ? $latest[count($latest) - 2] : end($latest);
    $v = backupVerifySet($target, $good, 'a new long passphrase');
    ok('a good backup verifies', $v['ok'] === true && $v['checked'] >= 3 && !$v['errors'], json_encode($v));
    $threw = null;
    try { backupVerifySet($target, $good, 'not the passphrase'); } catch (Throwable $e) { $threw = $e; }
    ok('verify with a wrong passphrase is refused', $threw instanceof BackupWrongPassphrase);
    $pp = "$folder/backup/pool/$name";
    $orig = file_get_contents($pp);
    file_put_contents($pp, substr($orig, 0, 3000) . chr(ord($orig[3000]) ^ 1) . substr($orig, 3001));
    $v = backupVerifySet($target, $good, 'a new long passphrase');
    ok('a damaged stored file fails verification, and is named', $v['ok'] === false && $v['errors'] && str_contains(implode(' ', $v['errors']), $f2['key']), json_encode($v['errors']));
    file_put_contents($pp, $orig);

    $runRow = (int)$conn->query("SELECT id FROM backup_runs WHERE set_name = " . $conn->quote($good))->fetchColumn();
    $err2 = fn(callable $f) => (function () use ($f) { try { $f(); return null; } catch (BackupsInputError $e) { return $e->getMessage(); } })();
    ok('service verify: a wrong passphrase is an input error', $err2(fn() => BackupsService::verify($conn, $runRow, 'nope nope nope', $admin)) === 'err_passphrase_wrong');
    $vr = BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin);
    $row = $conn->query("SELECT verify_status, verified_by, verified_at FROM backup_runs WHERE id = $runRow")->fetch(PDO::FETCH_ASSOC);
    ok('service verify: the result is recorded on the run', $vr['ok'] && $row['verify_status'] === 'ok' && (int)$row['verified_by'] === $admin && $row['verified_at'] !== null, json_encode($row));

    section('Keyrings and authenticity');
    $origKeyring = json_decode((string)file_get_contents("$folder/backup/keyring.json"), true);
    $other_kr = backupNewKeyring('someone else entirely', ...$fast);
    backupWriteKeyring($target, $other_kr['keyring']);
    ok('a different keyring does not overwrite the old one: it is kept beside it',
       count(array_filter($target->listKeys(''), fn($k) => preg_match('#^keyring-[0-9a-f]{16}\.json$#', $k))) >= 1, json_encode($target->listKeys('')));
    $threw = null;
    try { $o = backupOpenSet($target, $good, 'a new long passphrase'); } catch (Throwable $e) { $threw = $e; }
    ok('an old set still opens with its own (correct) passphrase after a new keyring was written', $threw === null, $threw ? get_class($threw) . ': ' . $threw->getMessage() : '');
    $threw = null;
    try { backupOpenSet($target, $good, 'not the passphrase at all'); } catch (Throwable $e) { $threw = $e; }
    ok('...and a wrong passphrase is still refused', $threw instanceof BackupWrongPassphrase, $threw ? get_class($threw) : 'opened');
    backupWriteKeyring($target, $origKeyring);

    $dkPath = "$folder/backup/sets/$good/datakey.bin";
    $dkOrig = file_get_contents($dkPath);
    file_put_contents($dkPath, backupSealKey(random_bytes(32), base64_decode($origKeyring['public'])));
    $threw = null;
    try { backupOpenSet($target, $good, 'a new long passphrase'); } catch (Throwable $e) { $threw = $e; }
    ok('a set re-sealed by someone with only the public key is refused (not authentic)', $threw instanceof BackupCorrupt, $threw ? get_class($threw) . ': ' . $threw->getMessage() : 'opened');
    file_put_contents($dkPath, $dkOrig);
    ok('restore only writes into the known upload folders', backupRestoreDirAllowed('uploads') && backupRestoreDirAllowed('forms/images')
       && !backupRestoreDirAllowed('includes') && !backupRestoreDirAllowed('uploads/../includes') && !backupRestoreDirAllowed(''));

    section('Restore');
    $rc = zzRestoreConn($conn, $restoreDb);
    if (!$rc) {
        echo "  SKIP restore (this login may not create the scratch database $restoreDb)\n";
    } else {
        $cleanup[] = fn() => $conn->exec("DROP DATABASE IF EXISTS `$restoreDb`");
        $newRoot = "$work/newapp";
        $newKey  = "$work/keys/freeitsm.key";
        $newFiles = "$work/newfiles";
        mkdir($newRoot); mkdir($newFiles);
        $log = [];
        $logger = function (string $m) use (&$log) { $log[] = $m; };
        $restore = new BackupRestore($target, $good, 'a new long passphrase', $rc, $newRoot, $newKey, false, $logger, new LocalDriver($newFiles));
        $res = $restore->run();
        ok('restore: ok', $res['ok'] === true && !$res['errors'], json_encode($res['errors'] ?? null));
        ok('restore: the key file is the live one', is_file($newKey) && trim((string)file_get_contents($newKey)) === trim((string)file_get_contents(ENCRYPTION_KEY_PATH)));
        ok('restore: the key file is private', DIRECTORY_SEPARATOR === '\\' || (fileperms($newKey) & 0077) === 0, decoct(fileperms($newKey) & 0777));
        $liveCounts = zzTableCounts($conn);
        $newCounts = zzTableCounts($rc);
        // backup_runs and system_settings change after the backup (this test writes them); the rest must match.
        unset($liveCounts['backup_runs'], $newCounts['backup_runs'], $liveCounts['system_settings'], $newCounts['system_settings'],
              $liveCounts['job_runs'], $newCounts['job_runs'], $liveCounts['job_schedules'], $newCounts['job_schedules']);
        ok('restore: every table comes back with its rows', $newCounts === $liveCounts,
           json_encode(array_diff_assoc($newCounts, $liveCounts) + array_diff_assoc($liveCounts, $newCounts)));
        ok('restore: the upload folder file is back', @file_get_contents("$newRoot/uploads/" . basename($upDir) . '/note.txt') === "$marker in a dir file");
        $fs = new LocalDriver($newFiles);
        $back = "$work/f2.back";
        $fs->readTo($f2['key'], $back);
        ok('restore: Files bytes are back in the Files store', hash_file('sha256', $back) === hash('sha256', $f2['bytes']));
        ok('restore: scheduled backups are paused on the restored install',
           $rc->query("SELECT setting_value FROM system_settings WHERE setting_key = 'backup_schedule'")->fetchColumn() === 'off');
        ok('restore: the restored install gets a new install id',
           (string)$rc->query("SELECT setting_value FROM system_settings WHERE setting_key = 'backup_install_id'")->fetchColumn() !== backupSetting($conn, 'backup_install_id'));

        // Again, into what is now an install in use: refused without force, nothing touched.
        $rc->exec("UPDATE analysts SET last_login_datetime = UTC_TIMESTAMP() ORDER BY id LIMIT 1");
        $rc->exec("CREATE TABLE zz_marker (id INT)");
        $threw = null;
        try { (new BackupRestore($target, $good, 'a new long passphrase', $rc, $newRoot, $newKey, false, $logger, new LocalDriver($newFiles)))->run(); }
        catch (Throwable $e) { $threw = $e; }
        ok('restore into a database in use is refused without --force', $threw instanceof BackupRestoreRefused, $threw ? get_class($threw) . ': ' . $threw->getMessage() : 'ran');
        ok('...and nothing was dropped', (bool)$rc->query("SHOW TABLES LIKE 'zz_marker'")->fetchColumn());

        // A different key with a database in use: refused even when the database part is forced? No - force allows both.
        file_put_contents($newKey, str_repeat('ab', 32));
        $threw = null;
        try { (new BackupRestore($target, $good, 'a new long passphrase', $rc, $newRoot, $newKey, false, $logger, new LocalDriver($newFiles)))->run(); }
        catch (Throwable $e) { $threw = $e; }
        ok('a different key on an install in use is refused without --force', $threw instanceof BackupRestoreRefused);
        ok('...and the key is untouched', trim((string)file_get_contents($newKey)) === str_repeat('ab', 32));
        $res = (new BackupRestore($target, $good, 'a new long passphrase', $rc, $newRoot, $newKey, true, $logger, new LocalDriver($newFiles)))->run();
        ok('with --force it restores, replacing tables and key', $res['ok'] && !$rc->query("SHOW TABLES LIKE 'zz_marker'")->fetchColumn()
           && trim((string)file_get_contents($newKey)) === trim((string)file_get_contents(ENCRYPTION_KEY_PATH)), json_encode($res['errors']));

        // A fresh install (only the seed admin, never signed in, no encrypted settings) with its own new key: replaced without --force.
        $rc2 = zzRestoreConn($conn, $restoreDb);
        $rc2->exec("CREATE TABLE analysts (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50), last_login_datetime DATETIME NULL)");
        $rc2->exec("INSERT INTO analysts (username) VALUES ('admin')");
        $rc2->exec("CREATE TABLE system_settings (setting_key VARCHAR(100) PRIMARY KEY, setting_value TEXT)");
        file_put_contents($newKey, str_repeat('cd', 32));
        $res = (new BackupRestore($target, $good, 'a new long passphrase', $rc2, $newRoot, $newKey, false, $logger, new LocalDriver($newFiles)))->run();
        ok('a fresh install\'s new key is replaced without --force', $res['ok'] && trim((string)file_get_contents($newKey)) === trim((string)file_get_contents(ENCRYPTION_KEY_PATH)),
           json_encode($res['errors']));

        $threw = null;
        try { (new BackupRestore($target, $good, 'wrong passphrase!!', $rc2, $newRoot, $newKey, true, $logger, new LocalDriver($newFiles)))->run(); }
        catch (Throwable $e) { $threw = $e; }
        ok('a wrong passphrase restores nothing', $threw instanceof BackupWrongPassphrase);

        section('Command line');
        $php = PHP_BINARY;
        $cmd = fn(string $args, string $env = '') => trim((string)shell_exec("cd " . escapeshellarg($appRoot) . " && $env $php scripts/backup_restore.php $args 2>&1; echo \"EXIT=\$?\""));
        $o = $cmd('--folder=' . escapeshellarg($folder) . ' --list');
        ok('--list shows the backups', str_contains($o, $good) && str_ends_with($o, 'EXIT=0'), $o);
        $o = $cmd('--folder=' . escapeshellarg($folder) . " --set=latest --database=$restoreDb --app-root=" . escapeshellarg($newRoot)
                  . ' --key-path=' . escapeshellarg($newKey) . ' --yes --force --no-verify-schema', 'FREEITSM_BACKUP_PASSPHRASE=wrong-passphrase-here');
        ok('a wrong passphrase exits non-zero without a stack trace', !str_ends_with($o, 'EXIT=0') && !str_contains($o, 'Stack trace') && !str_contains($o, '#0 '), $o);
        $o = $cmd('--folder=' . escapeshellarg($folder) . " --set=$good --database=$restoreDb --app-root=" . escapeshellarg($newRoot)
                  . ' --key-path=' . escapeshellarg($newKey) . ' --yes --force --no-verify-schema', "FREEITSM_BACKUP_PASSPHRASE='a new long passphrase'");
        ok('a full restore from the command line exits 0', str_ends_with($o, 'EXIT=0'), $o);
        ok('the passphrase never appears in the output', !str_contains($o, 'a new long passphrase'));
        $o = $cmd('--folder=' . escapeshellarg($folder) . " --set=latest --database=$restoreDb --yes --force", "FREEITSM_BACKUP_PASSPHRASE='a new long passphrase'");
        ok('a restore into another database must say where the key and files go (exit 2)', str_ends_with($o, 'EXIT=2') && str_contains($o, '--app-root'), $o);
        $o = $cmd('--bogus-flag');
        ok('an unknown flag is a usage error (exit 2)', str_ends_with($o, 'EXIT=2'), $o);
    }

    section('The API (over HTTP)');
    $base = rtrim(getenv('FREEITSM_TEST_URL') ?: 'http://localhost', '/') . '/';
    $sessDir = rtrim(getenv('FREEITSM_SESS_DIR') ?: (ini_get('session.save_path') ?: sys_get_temp_dir()), '/\\');
    $conn->prepare("INSERT INTO analysts (username, password_hash, full_name, email, is_active, is_admin, created_datetime)
                    VALUES (?, 'x', 'ZZ Backup NonAdmin', 'zz-bk@example.invalid', 1, 0, UTC_TIMESTAMP())")->execute(['zzbk' . bin2hex(random_bytes(3))]);
    $nonAdmin = (int)$conn->lastInsertId();
    $cleanup[] = fn() => $conn->prepare('DELETE FROM analysts WHERE id = ?')->execute([$nonAdmin]);
    $mkSess = function (int $id, string $csrf) use ($sessDir, &$cleanup): string {
        $sid = 'zzbk' . bin2hex(random_bytes(8));
        file_put_contents("$sessDir/sess_$sid", 'analyst_id|i:' . $id . ';csrf_token|s:' . strlen($csrf) . ':"' . $csrf . '";');
        @chmod("$sessDir/sess_$sid", 0666);
        $cleanup[] = fn() => @unlink("$sessDir/sess_$sid");
        return $sid;
    };
    $http = function (string $sid, ?array $post = null, ?string $csrf = null) use ($base): array {
        $ch = curl_init($base . 'api/system/backups.php');
        $h = ['Content-Type: application/json'];
        if ($csrf !== null) $h[] = 'X-CSRF-Token: ' . $csrf;
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 120, CURLOPT_COOKIE => 'PHPSESSID=' . $sid, CURLOPT_HTTPHEADER => $h]);
        if ($post !== null) { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post)); }
        $body = (string)curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$code, json_decode($body, true), $body];
    };
    // The web server runs as another user than this test: let it read the folder target the test made.
    if (DIRECTORY_SEPARATOR === '/') exec('chmod -R a+rwX ' . escapeshellarg($folder) . ' ' . escapeshellarg($work));
    $tok = bin2hex(random_bytes(16));
    $adminSid = $mkSess($admin, $tok);
    $userSid  = $mkSess($nonAdmin, $tok);
    [$code, $j] = $http($userSid);
    ok('a non-administrator gets 403', $code === 403, (string)$code);
    [$code, $j, $raw] = $http($adminSid);
    ok('an administrator gets the settings and the runs', $code === 200 && !empty($j['success']) && is_array($j['runs']) && isset($j['settings']['target']), substr($raw, 0, 200));
    ok('the response holds no pool name key and no keyring secret',
       !str_contains($raw, bin2hex(backupPoolNameKey($conn))) && !str_contains($raw, 'secret_enc'));
    [$code, $j] = $http($adminSid, ['action' => 'save_schedule', 'mode' => 'off', 'keep' => 3]);
    ok('a write without the CSRF token is refused', $code === 403 || $code === 419 || empty($j['success']), (string)$code);
    [$code, $j] = $http($adminSid, ['action' => 'save_schedule', 'mode' => 'daily', 'time' => '04:15', 'keep' => 3], $tok);
    ok('a write with the token works', $code === 200 && !empty($j['success']) && backupSetting($conn, 'backup_time') === '04:15', json_encode($j));
    [$code, $j] = $http($adminSid, ['action' => 'save_schedule', 'mode' => 'daily', 'time' => '99:99', 'keep' => 3], $tok);
    ok('an input error comes back translated', $code === 400 && ($j['error'] ?? '') === t('system.backups.err_schedule_time') && !str_contains((string)$j['error'], 'err_'), json_encode($j));
    $okRun = (int)$conn->query("SELECT id FROM backup_runs WHERE status = 'ok' ORDER BY id DESC LIMIT 1")->fetchColumn();
    [$code, $j] = $http($adminSid, ['action' => 'verify', 'run_id' => $okRun, 'passphrase' => 'definitely wrong'], $tok);
    ok('verify with a wrong passphrase says so', $code === 400 && ($j['error'] ?? '') === t('system.backups.err_passphrase_wrong'), json_encode($j));
    [$code, $j] = $http($adminSid, ['action' => 'verify', 'run_id' => $okRun, 'passphrase' => 'a new long passphrase'], $tok);
    ok('verify with the passphrase works over HTTP', $code === 200 && !empty($j['verify']['ok']), json_encode($j));
    [$code, $j] = $http($adminSid, ['action' => 'nonsense'], $tok);
    ok('an unknown action is a 400', $code === 400);
    BackupsService::saveSchedule($conn, 'off', null, null, 3, $admin);
    section('The backup job');
    ok('the job script exists', is_file("$appRoot/cron/backup.php"));
    BackupsService::saveSchedule($conn, 'daily', null, '03:00', 3, $admin);
    ok('the job is needed once a schedule is set', jobRegistry()['backup']['needed']($conn) === true);
    BackupsService::saveSchedule($conn, 'off', null, null, 3, $admin);
} catch (Throwable $e) {
    ok('no unexpected error', false, get_class($e) . ': ' . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine());
} finally {
    foreach (array_reverse($cleanup) as $c) { try { $c(); } catch (Throwable $ignored) {} }
    $rm = function (string $d) use (&$rm) {
        foreach (glob("$d/{,.}*", GLOB_BRACE) ?: [] as $f) {
            if (in_array(basename($f), ['.', '..'], true)) continue;
            is_dir($f) && !is_link($f) ? $rm($f) : @unlink($f);
        }
        @rmdir($d);
    };
    $rm($work);
}

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
