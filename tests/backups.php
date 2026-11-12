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

$pass = 0; $fail = 0;
function ok(string $label, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; printf("  PASS %-70s\n", $label); }
    else       { $fail++; printf("  FAIL %-70s %s\n", $label, $detail); }
}
function section(string $t): void { echo "\n$t\n" . str_repeat('-', 72) . "\n"; }

echo "\nBackups\n" . str_repeat('=', 72) . "\n";

// ── Pure checks (no database) ──
section('S3 list response parsing');
$xml = '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
     . '<Name>b</Name><Prefix>p/</Prefix><KeyCount>2</KeyCount><IsTruncated>true</IsTruncated>'
     . '<NextContinuationToken>t+1/=</NextContinuationToken>'
     . '<Contents><Key>p/backup/a&amp;b.txt</Key><Size>3</Size></Contents>'
     . '<Contents><Key>p/backup/c.txt</Key><Size>4</Size></Contents></ListBucketResult>';
$r = s3ParseListObjects($xml);
ok('keys are read (entities decoded)', $r['keys'] === ['p/backup/a&b.txt', 'p/backup/c.txt'], json_encode($r));
ok('continuation token when truncated', $r['next'] === 't+1/=');
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
