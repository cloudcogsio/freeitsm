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
// Never email anyone (tests/README): what a backup tells people (includes/backup/notify.php) is recorded instead.
$zzBackupMails = [];
BackupNotify::$mailer = function (string $to, string $subject, string $html) use (&$zzBackupMails): void { $zzBackupMails[] = [$to, $subject]; };
BackupsService::$kdfLimit = 1000;   // this test checks many passphrases; the throttle has its own check below

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
    /** Reads of this test's own files (not of the install's). */
    public int $reads = 0;
    private LocalDriver $d;
    /**
     * @param StorageDriver|null $real  the install's own Files storage: a key the stand-in does not hold (Files
     *                                  content the install already had) is read from there, so a backup of an
     *                                  install with Files content runs as it would without the test
     */
    public function __construct(string $dir, private ?StorageDriver $real = null) { $this->d = new LocalDriver($dir); }
    private function up(): void { if ($this->down) throw new StorageUnavailable('Storage could not be reached: test stand-in is down'); }
    private function holder(string $key): StorageDriver { return $this->real !== null && $this->d->size($key) === null ? $this->real : $this->d; }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->up(); $this->d->putFile($key, $localPath, $move); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { $this->up(); $this->holder($key)->readRange($key, $start, $end, $sink); }
    public function readTo(string $key, string $localPath): void
    {
        $this->up();
        $h = $this->holder($key);
        if ($h === $this->d) $this->reads++;
        $h->readTo($key, $localPath);
    }
    public function size(string $key): ?int { $this->up(); return $this->holder($key)->size($key); }
    public function delete(string $key): void { $this->up(); $this->d->delete($key); }
    public function label(): string { return 'zz-fake-s3'; }
}
/** Backup target stand-in: a folder target that counts size checks and can be switched off. */
final class ZzBkFlakyTarget implements StorageDriver, StorageLister
{
    public bool $down = false;
    public int $sizeCalls = 0;
    private LocalDriver $d;
    public function __construct(string $dir) { $this->d = new LocalDriver($dir); }
    private function up(): void { if ($this->down) throw new StorageUnavailable('Storage could not be reached: test target is down'); }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->up(); $this->d->putFile($key, $localPath, $move); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { $this->up(); $this->d->readRange($key, $start, $end, $sink); }
    public function readTo(string $key, string $localPath): void { $this->up(); $this->d->readTo($key, $localPath); }
    public function size(string $key): ?int { $this->up(); $this->sizeCalls++; return $this->d->size($key); }
    public function delete(string $key): void { $this->up(); $this->d->delete($key); }
    public function listKeys(string $prefix): array { $this->up(); return $this->d->listKeys($prefix); }
    public function listObjects(string $prefix): array { $this->up(); return $this->d->listObjects($prefix); }
    public function eachObject(string $prefix, callable $fn): void { $this->up(); $this->d->eachObject($prefix, $fn); }
    public function label(): string { return 'zz-flaky-target'; }
}
/**
 * A target holding a very large pool, made up as it is listed (nothing stored): $n objects with
 * their sealed keys, and one set whose refs.txt names every other one. For memory checks.
 */
final class ZzBkBigPool implements StorageDriver, StorageLister
{
    public int $deleted = 0;
    public function __construct(private int $n) {}
    public static function name(int $i): string { return hash('sha256', "zz-pool-$i"); }
    public function eachObject(string $prefix, callable $fn): void
    {
        if ($prefix === 'pool/') {
            for ($i = 0; $i < $this->n; $i++) {
                $h = self::name($i);
                $fn("pool/$h", backupEncryptedSize(1000), 1000);          // old enough to collect
                $fn("pool/$h.key", BACKUP_SEALED_KEY_SIZE, 1000);
            }
        } elseif ($prefix === 'sets/') {
            foreach (['done.json', 'refs.txt', 'owner.json'] as $o) $fn("sets/20000101T000000Z/$o", 10, time());
        }
    }
    public function listObjects(string $prefix): array { $o = []; $this->eachObject($prefix, function ($k, $s, $m) use (&$o) { $o[$k] = ['size' => $s, 'mtime' => $m]; }); return $o; }
    public function listKeys(string $prefix): array { return array_keys($this->listObjects($prefix)); }
    public function readTo(string $key, string $localPath): void
    {
        if (str_ends_with($key, 'refs.txt')) {
            $fh = fopen($localPath, 'wb');
            for ($i = 0; $i < $this->n; $i += 2) fwrite($fh, self::name($i) . "\n");
            fclose($fh);
        } else {
            file_put_contents($localPath, json_encode(['install_id' => 'someone-else']));
        }
    }
    public function putFile(string $key, string $localPath, bool $move = false): void {}
    public function readRange(string $key, int $start, int $end, callable $sink): void {}
    public function size(string $key): ?int { return null; }
    public function delete(string $key): void { $this->deleted++; }
    public function label(): string { return 'zz-big-pool'; }
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

section('The Storage and backups permission');
require_once "$root/includes/rbac.php";
$sb = capKey(Cap::FILES_STORAGE_BACKUPS);
ok('it is a sensitive Files permission', capExists($sb) && capModule($sb) === 'files' && capIsSensitive($sb));
ok('"Manage everything in Files" does not include it', !in_array($sb, capExpandUmbrellas([capKey(Cap::FILES_MANAGE)]), true)
   && in_array(capKey(Cap::FILES_STORAGE), capExpandUmbrellas([capKey(Cap::FILES_MANAGE)]), true));
$sbMeta = capGroups()['files']['capabilities'][$sb] ?? [];
ok('Roles shows it with the settings, marked as granted on its own', ($sbMeta['outside_umbrella'] ?? null) === true && ($sbMeta['everyday'] ?? null) === false
   && ($sbMeta['sensitive'] ?? null) === true, json_encode($sbMeta));
ok('the capability registry is still consistent', capSelfCheck() === [], json_encode(capSelfCheck()));

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
// A passphrase change makes a NEW keypair; the old ones travel inside, under the new passphrase.
$before = random_bytes(32);
$sealedBefore = backupSealKey($before, $keys['public']);
$ch = backupChangeKeyring($kr['keyring'], 'correct horse battery', 'a brand new passphrase');
$k2 = backupUnlockKeyring($ch['keyring'], 'a brand new passphrase');
ok('change: a new keypair, the same pool name key', $k2['public'] !== $keys['public'] && base64_encode($k2['public']) === $ch['public']
   && $k2['pool_name_key'] === $keys['pool_name_key'] && count($k2['previous']) === 1);
$after = random_bytes(32);
$sealedAfter = backupSealKey($after, $k2['public']);
ok('change: the new passphrase opens what was sealed before and after it', backupOpenKeyAny($sealedBefore, $k2) === $before && backupOpenKeyAny($sealedAfter, $k2) === $after);
$threw = null;
try { backupOpenKeyAny($sealedAfter, $keys); } catch (Throwable $e) { $threw = $e; }
ok('change: the old passphrase\'s keys cannot open anything sealed after it', $threw instanceof BackupCorrupt && backupOpenKeyAny($sealedBefore, $keys) === $before);
$threw = null;
try { backupUnlockKeyring($ch['keyring'], 'correct horse battery'); } catch (Throwable $e) { $threw = $e; }
ok('change: the old passphrase does not open the new keyring', $threw instanceof BackupWrongPassphrase);
$ch2 = backupChangeKeyring($ch['keyring'], 'a brand new passphrase', 'a third passphrase here');
ok('change again: every earlier keypair is kept', count(backupUnlockKeyring($ch2['keyring'], 'a third passphrase here')['previous']) === 2);
$threw = null;
try { backupChangeKeyring($kr['keyring'], 'not the passphrase', 'whatever else'); } catch (Throwable $e) { $threw = $e; }
ok('change with a wrong old passphrase is refused', $threw instanceof BackupWrongPassphrase);

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
// Unique per run: two runs on one database (two people, or a reviewer) must never share or drop each other's.
$restoreDb = $dbName . '_zzrestore_' . bin2hex(random_bytes(4));
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
/**
 * Rewrites a dump as one cut off exactly between two statements: its first $keep statements
 * (null = all of them), no end record.
 */
function zzDumpWithoutEnd(string $in, string $out, ?int $keep = null): void {
    $gz = gzopen($in, 'rb');
    $w = gzopen($out, 'wb6');
    $n = 0;
    while (($sql = backupDumpNext($gz)) !== null && ($keep === null || $n < $keep)) {
        if (str_starts_with($sql, BACKUP_DUMP_END)) break;
        gzwrite($w, pack('N', strlen($sql)) . $sql);
        $n++;
    }
    gzclose($gz);
    gzclose($w);
}
/** An open set's file entries as an array (small test sets only); the set is closed. */
function zzSetFiles(array $open): array {
    $a = iterator_to_array(backupSetFiles($open), false);
    backupCloseSet($open);
    return $a;
}
/** A dump of one table only (and the session SET statements), with its own end record. */
function zzDumpOnlyTable(string $in, string $out, string $table): void {
    $gz = gzopen($in, 'rb');
    $w = gzopen($out, 'wb6');
    $n = 0;
    $q = backupIdent($table);
    while (($sql = backupDumpNext($gz)) !== null) {
        if (str_starts_with($sql, BACKUP_DUMP_END)) break;
        if (!str_starts_with($sql, 'SET ') && !str_contains(substr($sql, 0, 200), $q)) continue;
        gzwrite($w, pack('N', strlen($sql)) . $sql);
        $n++;
    }
    $end = BACKUP_DUMP_END . $n;
    gzwrite($w, pack('N', strlen($end)) . $end);
    gzclose($gz);
    gzclose($w);
}
$work = sys_get_temp_dir() . '/zz-bk-' . bin2hex(random_bytes(4));
mkdir($work);
$cleanup = [];   // closures run at the end, newest first
// The bell rows the backup alerts leave (includes/backup/notify.php).
$zzNotifStart = (int)$conn->query('SELECT COALESCE(MAX(id), 0) FROM notifications')->fetchColumn();
$cleanup[] = fn() => $conn->prepare("DELETE FROM notifications WHERE id > ? AND entity_type = 'backup'")->execute([$zzNotifStart]);

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
    $every = implode('', array_map('chr', range(0, 255))) . "'\\\"\x1a\r\n\x00";
    $ins->bindValue(1, 'every byte'); $ins->bindValue(2, $every, PDO::PARAM_LOB); $ins->bindValue(3, '2.00'); $ins->bindValue(4, null);
    $ins->execute();
    // DEFAULT CURRENT_TIMESTAMP and ON UPDATE columns (MySQL 8 reports them as DEFAULT_GENERATED, which
    // is data, not a generated column) holding OLD values, a real generated column, and BIT values.
    $conn->exec('DROP TABLE IF EXISTS zz_backup_ts');
    $conn->exec("CREATE TABLE zz_backup_ts (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                 created_datetime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                 flags BIT(8) NULL, small BIT(3) NULL, v INT NOT NULL DEFAULT 0, dbl INT AS (v * 2) VIRTUAL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $cleanup[] = fn() => $conn->exec('DROP TABLE IF EXISTS zz_backup_ts');
    $conn->exec("INSERT INTO zz_backup_ts (created_datetime, updated_at, flags, small, v) VALUES
                 ('2001-02-03 04:05:06', '2002-03-04 05:06:07', b'10100101', b'101', 7),
                 ('2010-10-10 10:10:10', NULL, b'00000000', b'000', 0),
                 ('2020-01-01 00:00:00', '2020-01-01 00:00:01', b'11111111', NULL, -3)");
    $tsRows = "SELECT id, created_datetime, IFNULL(updated_at, '<null>'), IFNULL(HEX(flags), '<null>'), IFNULL(HEX(small), '<null>'), v, dbl FROM zz_backup_ts ORDER BY id";

    $dump = "$work/db.dump";
    $conn->beginTransaction();
    $info = backupDumpDatabase($conn, $dump, 1024 * 1024);
    $conn->commit();
    $gzAll = gzopen($dump, 'rb'); $tsIns = ''; while (($s = backupDumpNext($gzAll)) !== null) if (str_starts_with($s, 'INSERT INTO `zz_backup_ts`')) $tsIns .= $s; gzclose($gzAll);
    ok('the dump keeps DEFAULT CURRENT_TIMESTAMP columns, skips the generated one, writes BIT as its number',
       str_contains($tsIns, '`created_datetime`') && str_contains($tsIns, "'2001-02-03 04:05:06'") && str_contains($tsIns, "'2002-03-04 05:06:07'")
       && !str_contains($tsIns, '`dbl`') && str_contains($tsIns, "'2002-03-04 05:06:07', 165, 5,"), substr($tsIns, 0, 400));
    ok('the dump counts every table',($info['tables']['zz_backup_t'] ?? null) === 5 && count($info['tables']) === count(zzTableCounts($conn)),
       json_encode($info['tables']['zz_backup_t'] ?? null));
    $threw = null;
    try { backupDumpDatabase($conn, "$work/x.dump"); } catch (Throwable $e) { $threw = $e; }
    ok('dumping outside a transaction is refused (no consistent snapshot)', $threw instanceof LogicException, $threw ? get_class($threw) : 'dumped');
    $largest = 0;
    $plain = 0;
    $gz = gzopen($dump, 'rb');
    while (strlen($l = backupGzRead($gz, 4)) === 4) { $sz = unpack('N', $l)[1]; $largest = max($largest, $sz); $plain += 4 + $sz; backupGzRead($gz, $sz); }
    gzclose($gz);
    // Compressed: smaller than what it holds (the 3 MiB random row cannot shrink, so it is the floor). Not a fixed
    // ceiling: the rest of the database is whatever the test database holds.
    ok('the dump is compressed (smaller than its contents, larger than the random row)', filesize($dump) > 3 * 1024 * 1024 && filesize($dump) < $plain,
       filesize($dump) . ' of ' . $plain);
    ok('binary values are not doubled in the dump (they must fit max_allowed_packet on restore)', $largest < 1.2 * strlen($big), "$largest vs " . strlen($big));

    // The end record: a dump cut off exactly between two statements is a well-formed, shorter
    // dump - without the end record it would replay "successfully" with part of the data.
    $chk = backupCheckDump($dump);
    ok('the dump ends with its end record, counting every statement before it', $chk['ended'] === true && $chk['statements'] > 10, json_encode($chk));
    zzDumpWithoutEnd($dump, "$work/between.dump", 12);
    $chk = backupCheckDump("$work/between.dump");
    ok('a dump cut off between two statements is seen to have no end record', $chk['ended'] === false && $chk['statements'] === 12, json_encode($chk));
    zzDumpWithoutEnd($dump, "$work/noend.dump");
    $chk = backupCheckDump("$work/noend.dump");
    ok('...and so is a dump without only its end record', $chk['ended'] === false && $chk['statements'] > 10, json_encode($chk));
    $gz = gzopen($dump, 'rb'); $whole = ''; while (!gzeof($gz)) $whole .= gzread($gz, 1 << 20); gzclose($gz);
    $extra = 'DROP TABLE IF EXISTS `zz_after_end`';
    file_put_contents("$work/after.dump", gzencode($whole . pack('N', strlen($extra)) . $extra));
    $threw = null;
    try { backupCheckDump("$work/after.dump"); } catch (Throwable $e) { $threw = $e; }
    ok('a statement after the end record is damage, not data', $threw instanceof RuntimeException, $threw ? $threw->getMessage() : 'accepted');
    $fake = BACKUP_DUMP_END . '3';
    $gz = gzopen("$work/fakeend.dump", 'wb6');
    foreach (['SET NAMES utf8mb4', $fake] as $s) gzwrite($gz, pack('N', strlen($s)) . $s);
    gzclose($gz);
    $threw = null;
    try { backupCheckDump("$work/fakeend.dump"); } catch (Throwable $e) { $threw = $e; }
    ok('an end record that does not count the statements before it is refused', $threw instanceof RuntimeException, $threw ? $threw->getMessage() : 'accepted');
    file_put_contents("$work/cut.dump", substr(file_get_contents($dump), 0, 2000));
    $threw = null;
    $chk = null;
    try { $chk = backupCheckDump("$work/cut.dump"); } catch (Throwable $e) { $threw = $e; }
    ok('a dump file cut off anywhere is never taken as complete', $threw instanceof RuntimeException || ($chk !== null && $chk['ended'] === false),
       $threw ? '' : json_encode($chk));

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
        ok('DEFAULT CURRENT_TIMESTAMP / ON UPDATE columns keep their old values, BIT values come back exactly',
           $rc->query($tsRows)->fetchAll(PDO::FETCH_NUM) === $conn->query($tsRows)->fetchAll(PDO::FETCH_NUM),
           json_encode($rc->query($tsRows)->fetchAll(PDO::FETCH_NUM)));
        $sum = fn(PDO $c, string $t) => (string)$c->query('CHECKSUM TABLE ' . $t)->fetch(PDO::FETCH_NUM)[1];
        ok('whole rows are identical (CHECKSUM TABLE) for both fixture tables',
           $sum($rc, 'zz_backup_ts') === $sum($conn, 'zz_backup_ts') && $sum($rc, 'zz_backup_t') === $sum($conn, 'zz_backup_t'));
        ok('the 3 MiB row comes back whole', hash('sha256', (string)$rc->query("SELECT b FROM zz_backup_t WHERE s = 'big'")->fetchColumn()) === hash('sha256', $big));
        ok('auto increment continues after the restored rows',
           (int)$rc->query("SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'zz_backup_t'")->fetchColumn() >= 5);
        $threw = null;
        try { backupReplayDump($rc, "$work/cut.dump"); } catch (Throwable $e) { $threw = $e; }
        ok('a truncated dump fails rather than restoring part of the data silently', $threw instanceof RuntimeException, $threw ? get_class($threw) : 'replayed');
        $threw = null;
        try { backupReplayDump(zzRestoreConn($conn, $restoreDb), "$work/between.dump"); } catch (Throwable $e) { $threw = $e; }
        ok('a dump cut off exactly between two statements fails too (no end record)',
           $threw instanceof RuntimeException && $threw->getMessage() === BACKUP_DUMP_INCOMPLETE, $threw ? $threw->getMessage() : 'replayed');
        $threw = null;
        try { backupReplayDump(zzRestoreConn($conn, $restoreDb), "$work/noend.dump"); } catch (Throwable $e) { $threw = $e; }
        ok('...and a dump without only its end record', $threw instanceof RuntimeException && $threw->getMessage() === BACKUP_DUMP_INCOMPLETE);
        // On a dump of the fixture table alone: the rest of the database may hold rows of any size
        // (the help index has a 1 MB row), which must not be what trips the limit.
        zzDumpOnlyTable($dump, "$work/fixture.dump", 'zz_backup_t');
        $n = backupReplayDump(zzRestoreConn($conn, $restoreDb), "$work/fixture.dump", null, 64 * 1024 * 1024);
        ok('control: the fixture table alone replays under a large enough max_allowed_packet', $n > 3, (string)$n);
        $threw = null;
        try { backupReplayDump(zzRestoreConn($conn, $restoreDb), "$work/fixture.dump", null, 1024 * 1024); } catch (Throwable $e) { $threw = $e; }
        ok('a row larger than the server\'s max_allowed_packet: a clear error naming the table',
           $threw instanceof RuntimeException && str_contains($threw->getMessage(), 'max_allowed_packet') && str_contains($threw->getMessage(), 'zz_backup_t'),
           $threw ? get_class($threw) . ': ' . $threw->getMessage() : 'replayed');
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
    $u2 = backupUnlockKeyring($kr2, 'a new long passphrase');
    ok('passphrase change: a new keypair for new backups, the old one kept inside', backupSetting($conn, 'backup_public_key') !== $pub
       && base64_encode($u2['public']) === backupSetting($conn, 'backup_public_key') && base64_encode($u2['previous'][0]['public'] ?? '') === $pub);
    ok('passphrase change: the old keyring is kept on the target', count(array_filter(backupTargetDriver(backupTargetConfig($conn))->listKeys(''),
       fn($k) => preg_match('#^keyring-[0-9a-f]{16}\.json$#', $k))) >= 1);
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
    // Not only by Test: every request the backup target makes checks its address and pins it (storageCheckedAddress()).
    $threw = null;
    try { backupTargetDriver(['type' => 's3', 'endpoint' => 'http://169.254.169.254', 'region' => 'us-east-1', 'bucket' => 'b', 'access_key_id' => 'k',
                              'secret' => 'x', 'prefix' => '', 'path_style' => true])->size('keyring.json'); } catch (Throwable $e) { $threw = $e; }
    ok('the backup target itself refuses a link-local address on every request', $threw instanceof StorageUnavailable && str_contains($threw->getMessage(), 'not allowed'),
       $threw ? $threw->getMessage() : 'requested');
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
    filesStorageReset();
    $fake = new ZzBkFakeS3($s3dir, filesActiveStore($conn));   // the install's own Files content stays readable
    FilesStorageCache::$drivers['active'] = $fake;
    $appRoot = dirname(__DIR__);
    $upDir = "$appRoot/uploads/zz-backup-test-" . bin2hex(random_bytes(3));
    mkdir($upDir, 0777, true);
    $cleanup[] = function () use ($upDir) { foreach (glob("$upDir/{,.}*", GLOB_BRACE) as $f) if (is_file($f)) @unlink($f); @rmdir($upDir); };
    $marker = 'ZZ-BACKUP-PLAINTEXT-MARKER-' . bin2hex(random_bytes(8));
    file_put_contents("$upDir/note.txt", "$marker in a dir file");
    file_put_contents("$upDir/.htaccess", 'Require all denied');
    file_put_contents("$upDir/web.config", '<configuration/>');
    file_put_contents("$upDir/.env", "ZZ=uploaded dot file");
    // A file in a store (FILE_STORES), walked from where the store lives (fileStoreDir()).
    $docRel = 'zz-backup-test-' . bin2hex(random_bytes(3)) . '/doc.txt';
    $docAbs = fileStorePath('documents', $docRel);
    @mkdir(dirname($docAbs), 0777, true);
    file_put_contents($docAbs, 'a document in its store');
    $cleanup[] = function () use ($docAbs) { @unlink($docAbs); @rmdir(dirname($docAbs)); };

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
    $threw = null;
    try { backupOpenSet($target, $set1, 'long enough passphrase'); } catch (Throwable $e) { $threw = $e; }
    ok('the passphrase from before the change cannot open a backup made after it', $threw instanceof BackupCorrupt || $threw instanceof BackupWrongPassphrase,
       $threw ? get_class($threw) : 'opened');
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
    $paths = array_map(fn($f) => $f['store'] . ':' . $f['path'], zzSetFiles($open));
    ok('the manifest lists the Files key', in_array('files:' . $f1['key'], $paths, true));
    ok('protection files (.htaccess, web.config) are not backed up: the install\'s own copies count',
       !array_filter($paths, fn($p) => str_ends_with($p, '/.htaccess') || str_ends_with($p, '/web.config')));
    ok('...but any other dot file is data, and is backed up', in_array('dir:uploads:' . basename($upDir) . '/.env', $paths, true));
    ok('the manifest lists the upload folder file',in_array('dir:uploads:' . basename($upDir) . '/note.txt', $paths, true), implode(', ', array_slice($paths, 0, 8)));
    ok('the manifest skips the Files storage folder in the folder walk', !array_filter($paths, fn($p) => str_starts_with($p, 'dir:uploads:files/')));
    ok('a store\'s file is named after the store\'s default folder (FILE_STORES)', in_array("dir:uploads/documents:$docRel", $paths, true));
    ok('...and not again as part of uploads/', !array_filter($paths, fn($p) => str_starts_with($p, 'dir:uploads:documents/')));
    ok('the manifest carries this install and the table counts',
       $open['manifest']['install_id'] === backupSetting($conn, 'backup_install_id') && ($open['manifest']['tables']['backup_runs'] ?? null) !== null);

    $r2 = $runner->run('manual', $admin);
    ok('second run: ok and nothing new uploaded', $r2['status'] === 'ok' && $r2['files_new'] === 0, json_encode($r2));
    $fake->reads = 0;
    $r2b = $runner->run('manual', $admin);
    ok('Files already in the backup are not downloaded again', $r2b['status'] === 'ok' && $fake->reads === 0, 'reads: ' . $fake->reads);
    // A reused pool object damaged in place (same size, not a backup object any more): the sample finds it.
    $victim = backupPoolName(backupPoolNameKey($conn), hash('sha256', $f2['bytes']));
    $vp = "$folder/backup/pool/$victim";
    $vOrig = file_get_contents($vp);
    file_put_contents($vp, str_repeat("\0", strlen($vOrig)));
    $runner->sampleSize = 1000;
    $rd = $runner->run('manual', $admin);
    ok('a damaged reused stored file is found by the sample: the run fails, saying so', $rd['status'] === 'failed'
       && $rd['error'] === backupT('err_pool_damaged') && !is_file($vp), json_encode($rd));
    $quarantined = glob("$folder/backup/quarantine/$victim.*") ?: [];
    ok('...the damaged object is moved aside (quarantine/), not deleted', count($quarantined) === 1 && is_file("$vp.key"), json_encode($quarantined));
    $rd2 = $runner->run('manual', $admin);
    ok('...and the next run stores it again', $rd2['status'] === 'ok' && $rd2['files_new'] >= 1 && is_file($vp), json_encode($rd2));
    $runner->sampleSize = 5;
    $mailsBefore = count($zzBackupMails);
    $bellsBefore = (int)$conn->query("SELECT COUNT(*) FROM notifications WHERE entity_type = 'backup'")->fetchColumn();
    $r2c = (new BackupRunner($conn, $target, $appRoot))->run('scheduled', null);   // the job's own way of telling
    ok('a backup that works tells nobody (no bell, no email)', $r2c['status'] === 'ok' && count($zzBackupMails) === $mailsBefore
       && (int)$conn->query("SELECT COUNT(*) FROM notifications WHERE entity_type = 'backup'")->fetchColumn() === $bellsBefore, json_encode($r2c));
    file_put_contents("$upDir/second.txt", 'another file ' . bin2hex(random_bytes(8)));
    $r3 = $runner->run('manual', $admin);
    ok('a new file: exactly one upload', $r3['status'] === 'ok' && $r3['files_new'] === 1, json_encode($r3));

    // The pool is listed once per run, not checked object by object (100,000 files = 200,000 requests).   (Plus the few sampled objects read back.)
    $flaky = new ZzBkFlakyTarget("$folder/backup");
    $fr = new BackupRunner($conn, $flaky, $appRoot, $mailer);
    $rf = $fr->run('manual', $admin);
    ok('a run checks the pool by listing it, not one request per file', $rf['status'] === 'ok' && $flaky->sizeCalls <= 2 + $fr->sampleSize && $rf['files_total'] >= 3,
       'size calls: ' . $flaky->sizeCalls . ', files: ' . $rf['files_total'] . ' ' . json_encode($rf['error']));

    // The target goes away after the database dump: failed, reported once, nothing complete.
    $mails = [];
    $fr->afterInventory = function () use ($flaky) { $flaky->down = true; };
    file_put_contents("$upDir/after-dump.txt", 'needs an upload ' . bin2hex(random_bytes(8)));
    $rd = $fr->run('scheduled', null);
    $fr->afterInventory = null;
    $flaky->down = false;
    ok('target down after the dump: the run fails', $rd['status'] === 'failed' && str_contains((string)$rd['error'], 'test target is down'), json_encode($rd));
    ok('target down after the dump: administrators are emailed once', count($mails) === 1);
    ok('target down after the dump: the set is not complete', $rd['set'] !== null && $target->size('sets/' . $rd['set'] . '/done.json') === null);
    $rowD = $conn->query('SELECT status, error_text FROM backup_runs WHERE id = ' . (int)$rd['run_id'])->fetch(PDO::FETCH_ASSOC);
    ok('target down after the dump: the run row says failed', $rowD && $rowD['status'] === 'failed' && (string)$rowD['error_text'] !== '');
    unlink("$upDir/after-dump.txt");

    // A long file phase must not lose the database connection to wait_timeout.
    $conn->exec('SET SESSION wait_timeout = 2');
    $runner->afterInventory = function () { sleep(3); };
    $rw = null;
    try { $rw = $runner->run('manual', $admin); } catch (Throwable $e) { $rw = ['status' => 'threw', 'error' => $e->getMessage()]; }
    $runner->afterInventory = null;
    if ($rw['status'] !== 'ok') $conn = connectToDatabase();
    ok('a file phase longer than wait_timeout: still ok', $rw['status'] === 'ok', json_encode($rw));

    // A file changed between its checksum and its encryption: the backup holds what was encrypted.
    file_put_contents("$upDir/changing.txt", 'before ' . bin2hex(random_bytes(8)));
    $after = 'after the change ' . bin2hex(random_bytes(8));
    $runner->beforeEncrypt = function (string $path) use ($upDir, $after) {
        if (str_ends_with(str_replace('\\', '/', $path), '/changing.txt')) file_put_contents("$upDir/changing.txt", $after);
    };
    $rch = $runner->run('manual', $admin);
    $runner->beforeEncrypt = null;
    $mch = array_values(array_filter(zzSetFiles(backupOpenSet($target, (string)$rch['set'], 'a new long passphrase')),
                                     fn($f) => str_ends_with($f['path'], '/changing.txt')));
    ok('a file changed mid-run: the manifest has the checksum of what was stored', $rch['status'] === 'ok' && $mch && $mch[0]['sha256'] === hash('sha256', $after),
       json_encode($mch));
    $vch = backupVerifySet($target, (string)$rch['set'], 'a new long passphrase');
    ok('...and that backup verifies', $vch['ok'] === true, json_encode($vch['errors']));
    unlink("$upDir/changing.txt");

    // No backup_runs table (Database Verification not run): administrators still hear about it.
    $mails = [];
    $conn->exec('RENAME TABLE backup_runs TO zz_backup_runs_hold');
    $rm = null;
    try { $rm = $runner->run('scheduled', null); } catch (Throwable $e) { $rm = ['status' => 'threw', 'error' => $e->getMessage()]; }
    $conn->exec('RENAME TABLE zz_backup_runs_hold TO backup_runs');
    ok('no history table: the run fails without throwing', $rm['status'] === 'failed', json_encode($rm));
    ok('no history table: administrators are emailed', count($mails) === 1, (string)count($mails));

    // A copy of this database on another server or under another name is another install.
    $realId = backupSetting($conn, 'backup_install_id');
    $realFp = backupSetting($conn, 'backup_install_fingerprint');
    ok('a run records where this install\'s database lives', $realFp !== '');
    backupSaveSetting($conn, 'backup_install_fingerprint', str_repeat('0', 64));
    $rcl = $runner->run('manual', $admin);
    $cloneId = backupSetting($conn, 'backup_install_id');
    ok('a cloned database gets its own install id', $rcl['status'] === 'ok' && $cloneId !== $realId && $cloneId !== '', json_encode($rcl));
    ok('...and says so in the run\'s warning', str_contains((string)$rcl['warning'], 'install'), (string)$rcl['warning']);
    $doneCl = json_decode((string)file_get_contents("$folder/backup/sets/{$rcl['set']}/done.json"), true);
    ok('...and its backups carry the new id', ($doneCl['install_id'] ?? '') === $cloneId);
    foreach ($target->listKeys("sets/{$rcl['set']}/") as $k) $target->delete($k);
    backupSaveSetting($conn, 'backup_install_id', $realId);
    backupSaveSetting($conn, 'backup_install_fingerprint', $realFp);

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
    $m6 = zzSetFiles(backupOpenSet($target, $r6['set'], 'a new long passphrase'));
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

    section('Memory on a large install');
    // 200,000 pooled files (400,000 objects): the pool is listed into a compact map, and the pool
    // clean-up streams both the listing and the references. Bounded, well inside a 128M CLI limit.
    $big = new ZzBkBigPool(200000);
    $bigRunner = new BackupRunner($conn, $big, $appRoot, fn() => null);
    gc_collect_cycles();
    $base = memory_get_usage();
    memory_reset_peak_usage();
    (new ReflectionMethod(BackupRunner::class, 'loadPool'))->invoke($bigRunner);
    $loadPeak = memory_get_peak_usage() - $base;
    ok('listing a 200,000-file pool stays under 40 MB', $loadPeak < 40 * 1048576, round($loadPeak / 1048576, 1) . ' MB');
    (new ReflectionProperty(BackupRunner::class, 'pool'))->setValue($bigRunner, []);
    gc_collect_cycles();
    $base = memory_get_usage();
    memory_reset_peak_usage();
    $pr = $bigRunner->prune(1, 'zz-not-this-install');
    $prunePeak = memory_get_peak_usage() - $base;
    ok('...and cleaning it up (half unreferenced) stays under 40 MB', $prunePeak < 40 * 1048576 && $big->deleted === 200000, round($prunePeak / 1048576, 1) . ' MB, deleted ' . $big->deleted);
    unset($big, $bigRunner);

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

    // A copy of $good whose dump has no end record, re-encrypted and re-signed as an install with
    // the keys would.
    $variant = function (string $name) use ($folder, $good, $target, $work): string {
        $src = "$folder/backup/sets/$good";
        $dst = "$folder/backup/sets/$name";
        @mkdir($dst, 0777, true);
        foreach (scandir($src) as $f) if (is_file("$src/$f")) copy("$src/$f", "$dst/$f");
        $open = backupOpenSet($target, $good, 'a new long passphrase');
        backupDecryptFile("$src/db.bin", "$work/variant.dump", $open['datakey']);
        zzDumpWithoutEnd("$work/variant.dump", "$work/variant-cut.dump");
        backupEncryptFile("$work/variant-cut.dump", "$dst/db.bin", $open['datakey']);
        $m = $open['manifest'];
        $m['set'] = $name;
        $m['db'] = ['size' => filesize("$work/variant-cut.dump"), 'sha256' => hash_file('sha256', "$work/variant-cut.dump")];
        $lines = file($open['files_path']);
        $lines[0] = json_encode($m, JSON_UNESCAPED_SLASHES) . "\n";
        file_put_contents("$work/variant-manifest", implode('', $lines));
        backupEncryptFile("$work/variant-manifest", "$dst/manifest.bin", $open['datakey']);
        file_put_contents("$dst/auth.txt", backupSetAuth($open['keys']['pool_name_key'], $name, (string)file_get_contents("$dst/datakey.bin"), (string)hash_file('sha256', "$dst/manifest.bin")));
        backupCloseSet($open);
        @unlink("$work/variant.dump"); @unlink("$work/variant-cut.dump"); @unlink("$work/variant-manifest");
        return $name;
    };
    $rmVariant = function (string $name) use ($folder): void {
        $d = "$folder/backup/sets/$name";
        foreach (scandir($d) as $f) if (is_file("$d/$f")) unlink("$d/$f");
        rmdir($d);
    };
    $cutSet = $variant('20000101T000001Z');
    $v = backupVerifySet($target, $cutSet, 'a new long passphrase');
    ok('verify: a dump without its end record fails', $v['ok'] === false
       && str_contains(implode(' ', $v['errors']), BACKUP_DUMP_INCOMPLETE), json_encode($v['errors']));
    $v = backupVerifySet($target, $good, 'a new long passphrase');
    ok('verify: a current backup passes with no warning', $v['ok'] === true && $v['warnings'] === [], json_encode($v));

    $runRow =(int)$conn->query("SELECT id FROM backup_runs WHERE set_name = " . $conn->quote($good))->fetchColumn();
    $err2 = fn(callable $f) => (function () use ($f) { try { $f(); return null; } catch (BackupsInputError $e) { return $e->getMessage(); } })();
    $cleanup[] = function () use ($rmVariant, $cutSet) { $rmVariant($cutSet); };
    ok('service verify: a wrong passphrase is an input error', $err2(fn() => BackupsService::verify($conn, $runRow, 'nope nope nope', $admin)) === 'err_passphrase_wrong');
    $vr = BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin);
    $row = $conn->query("SELECT verify_status, verified_by, verified_at FROM backup_runs WHERE id = $runRow")->fetch(PDO::FETCH_ASSOC);
    ok('service verify: the result is recorded on the run', $vr['ok'] && $row['verify_status'] === 'ok' && (int)$row['verified_by'] === $admin && $row['verified_at'] !== null, json_encode($row));
    // Passphrase checks are throttled (Argon2id per keyring tried): the limit, then a refusal.
    $conn->exec("DELETE FROM system_settings WHERE setting_key = 'backup_kdf_failures'");
    BackupsService::$kdfLimit = 2;
    $e1 = $err2(fn() => BackupsService::verify($conn, $runRow, 'nope nope nope', $admin));
    $e2 = $err2(fn() => BackupsService::verify($conn, $runRow, 'nope nope nope', $admin));
    $e3 = $err2(fn() => BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin));
    ok('wrong passphrases are throttled: after two, the next check is refused, even with the right passphrase',
       $e1 === 'err_passphrase_wrong' && $e2 === 'err_passphrase_wrong' && $e3 === 'err_throttled', json_encode([$e1, $e2, $e3]));
    $e4 = $err2(fn() => BackupsService::verify($conn, $runRow, 'a new long passphrase', 999999));
    ok('...for that analyst only: another one is not locked out', $e4 === null, (string)$e4);
    $conn->exec("DELETE FROM system_settings WHERE setting_key = 'backup_kdf_failures'");
    BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin);
    BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin);
    $e5 = $err2(fn() => BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin));
    ok('...and only wrong passphrases count: right ones never lock anyone out', $e5 === null, (string)$e5);
    $left = json_decode(backupSetting($conn, 'backup_kdf_failures', '{}'), true);
    ok('...a right passphrase gives its reservation back', empty($left['check:' . $admin]), json_encode($left));
    // A check still running holds its place, so requests sent in parallel cannot all slip past the count.
    backupSaveSetting($conn, 'backup_kdf_failures', json_encode(['check:' . $admin => [time() . ':running1', time() . ':running2']]));
    $e6 = $err2(fn() => BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin));
    ok('...checks still running count towards the limit', $e6 === 'err_throttled', (string)$e6);
    BackupsService::$kdfLimit = 1000;
    $conn->exec("DELETE FROM system_settings WHERE setting_key = 'backup_kdf_failures'");
    // A Verify holds its lock: a second one is refused, and pruning removes nothing meanwhile.
    $other = connectToDatabase();
    $other->prepare('SELECT GET_LOCK(?, 0)')->execute([backupVerifyLockName($conn)]);
    ok('a second Verify at the same time is refused', $err2(fn() => BackupsService::verify($conn, $runRow, 'a new long passphrase', $admin)) === 'err_verify_running');
    $pv = $runner->prune(1, backupSetting($conn, 'backup_install_id'));
    ok('...and pruning waits for it (removes nothing)', $pv['gc_skipped'] === true && $pv['sets_removed'] === 0 && $pv['pool_removed'] === 0, json_encode($pv));
    $other->prepare('SELECT RELEASE_LOCK(?)')->execute([backupVerifyLockName($conn)]);
    $other = null;
    // A verify the web server killed (timeout) never records its result: it must not say "running" for ever.
    $conn->exec("UPDATE backup_runs SET verify_status = 'running', verified_at = UTC_TIMESTAMP() - INTERVAL 4 HOUR WHERE id = $runRow");
    $byId = array_column(BackupsService::runs($conn), null, 'id');
    ok('a verify that stopped hours ago shows as interrupted', ($byId[$runRow]['verify_status'] ?? '') === 'interrupted', json_encode($byId[$runRow] ?? null));
    $conn->exec("UPDATE backup_runs SET verify_status = 'running', verified_at = UTC_TIMESTAMP() WHERE id = $runRow");
    $byId = array_column(BackupsService::runs($conn), null, 'id');
    ok('a verify started just now still shows as running', ($byId[$runRow]['verify_status'] ?? '') === 'running');
    $conn->exec("UPDATE backup_runs SET verify_status = 'ok' WHERE id = $runRow");
    // A backup whose process died (no job lock held) is not "running" either.
    $conn->exec("INSERT INTO backup_runs (kind, status, started_at) VALUES ('scheduled', 'running', UTC_TIMESTAMP() - INTERVAL 1 HOUR)");
    $deadRun = (int)$conn->lastInsertId();
    $byId = array_column(BackupsService::runs($conn), null, 'id');
    ok('a backup whose process died shows as interrupted', ($byId[$deadRun]['status'] ?? '') === 'interrupted', json_encode($byId[$deadRun] ?? null));
    $conn->exec("DELETE FROM backup_runs WHERE id = $deadRun");

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
    // Each store goes back to where it lives (fileStoreDir()); a scratch restore keeps them under its root.
    ok('restore writes a store\'s file to the store\'s folder', backupRestorePath($appRoot, 'uploads/documents', 'a/b.pdf') === fileStorePath('documents', 'a/b.pdf'));
    ok('...every store', backupRestorePath($appRoot, 'tickets/attachments', '12/x.png') === fileStorePath('ticket-attachments', '12/x.png'));
    ok('...and what is not a store stays where it was', backupRestorePath($appRoot, 'uploads', 'zz/x.txt') === "$appRoot/uploads/zz/x.txt");
    ok('...under another root for a restore elsewhere (--app-root)', backupRestorePath('/srv/scratch', 'uploads', 'documents/a.pdf') === '/srv/scratch/uploads/documents/a.pdf');
    ok('...and never outside the upload folders', backupRestorePath($appRoot, 'uploads', '../includes/x.php') === null && backupRestorePath($appRoot, 'includes', 'x.php') === null
       && backupRestorePath($appRoot, 'uploads', '/etc/passwd') === null && backupRestorePath($appRoot, 'uploads', '') === null);
    $folders = array_column(backupUploadFolders($appRoot), 'path', 'rel');
    ok('the backup walks every store in FILE_STORES from where it lives', !array_diff_key(array_flip(array_column(FILE_STORES, 'folder')), $folders)
       && $folders['war-room/attachments'] === fileStoreDir('war-room'), json_encode($folders));
    ok('...and keeps the persistence folders no store covers', isset($folders['uploads']) && !isset($folders[dirname((string)ENCRYPTION_KEY_PATH)]));

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
        ok('restore: a store\'s file is back in that store', @file_get_contents("$newRoot/uploads/documents/$docRel") === 'a document in its store');
        $fs = new LocalDriver($newFiles);
        $back = "$work/f2.back";
        $fs->readTo($f2['key'], $back);
        ok('restore: Files bytes are back in the Files store', hash_file('sha256', $back) === hash('sha256', $f2['bytes']));
        ok('restore: scheduled backups are paused on the restored install',
           $rc->query("SELECT setting_value FROM system_settings WHERE setting_key = 'backup_schedule'")->fetchColumn() === 'off');
        ok('restore: the restored install gets a new install id',
           (string)$rc->query("SELECT setting_value FROM system_settings WHERE setting_key = 'backup_install_id'")->fetchColumn() !== backupSetting($conn, 'backup_install_id'));

        // A dump without its end record is refused before anything is dropped.
        $rc->exec("CREATE TABLE zz_marker_end (id INT)");
        $threw = null;
        try { (new BackupRestore($target, $cutSet, 'a new long passphrase', $rc, $newRoot, $newKey, true, $logger, new LocalDriver($newFiles)))->run(); }
        catch (Throwable $e) { $threw = $e; }
        ok('restore: a dump without its end record is refused', $threw instanceof BackupCorrupt && $threw->getMessage() === BACKUP_DUMP_INCOMPLETE,
           $threw ? get_class($threw) . ': ' . $threw->getMessage() : 'ran');
        ok('...before anything was dropped', (bool)$rc->query("SHOW TABLES LIKE 'zz_marker_end'")->fetchColumn());
        $rc->exec('DROP TABLE zz_marker_end');

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

        // A trial restore must not write Files bytes where the restored settings point (the live Files store).
        $liveFiles = "$work/livefiles";
        mkdir($liveFiles);
        $oldRoot = $conn->query("SELECT setting_value FROM system_settings WHERE setting_key = 'files_storage_root'")->fetchColumn();
        backupSaveSetting($conn, 'files_storage_root', $liveFiles);
        $rt = $runner->run('manual', $admin);
        backupSaveSetting($conn, 'files_storage_root', $oldRoot === false ? null : (string)$oldRoot);
        filesStorageReset();
        FilesStorageCache::$drivers['active'] = $fake;
        $newRoot3 = "$work/newapp3";
        mkdir($newRoot3);
        $o = $cmd('--folder=' . escapeshellarg($folder) . " --set={$rt['set']} --database=$restoreDb --app-root=" . escapeshellarg($newRoot3)
                  . ' --key-path=' . escapeshellarg("$work/keys3/freeitsm.key") . ' --yes --force --no-verify-schema', "FREEITSM_BACKUP_PASSPHRASE='a new long passphrase'");
        $liveLeft = (new LocalDriver($liveFiles))->listKeys('');
        ok('a trial restore leaves the restored settings\' Files store alone', $rt['status'] === 'ok' && str_ends_with($o, 'EXIT=0') && $liveLeft === [],
           json_encode(array_slice($liveLeft, 0, 3)) . ' ' . $o);
        ok('...and puts the Files bytes under --app-root', @hash_file('sha256', "$newRoot3/uploads/files/{$f2['key']}") === hash('sha256', $f2['bytes']));
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
        // Stamped with the session epoch as a real sign-in is: after any restore, an unstamped
        // session is ended by the maintenance gate (backupSessionEpochGate).
        $epoch = function_exists('backupSessionEpoch') ? backupSessionEpoch() : '';
        file_put_contents("$sessDir/sess_$sid", 'analyst_id|i:' . $id . ';csrf_token|s:' . strlen($csrf) . ':"' . $csrf . '";'
                                               . ($epoch !== '' ? 'session_epoch|s:' . strlen($epoch) . ':"' . $epoch . '";' : ''));
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
    $conn->exec("DELETE FROM system_settings WHERE setting_key = 'backup_kdf_failures'");   // the web process counts passphrase checks too
    $tok = bin2hex(random_bytes(16));
    $adminSid = $mkSess($admin, $tok);
    $userSid  = $mkSess($nonAdmin, $tok);
    [$code, $j] = $http($userSid);
    ok('a non-administrator gets 403', $code === 403, (string)$code);

    // Storage and backups (wiki S3): its own grant, never part of "Manage everything in Files".
    $page = function (string $sid) use ($base): int {
        $ch = curl_init($base . 'system/backups/');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_COOKIE => 'PHPSESSID=' . $sid, CURLOPT_FOLLOWLOCATION => false]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $code;
    };
    $conn->prepare("INSERT INTO rbac_roles (name, is_active) VALUES ('ZZ backups permission', 1)")->execute();
    $zzRole = (int)$conn->lastInsertId();
    $cleanup[] = function () use ($conn, $zzRole) {
        $conn->prepare('DELETE FROM rbac_analyst_roles WHERE role_id = ?')->execute([$zzRole]);
        $conn->prepare('DELETE FROM rbac_role_capabilities WHERE role_id = ?')->execute([$zzRole]);
        $conn->prepare('DELETE FROM rbac_roles WHERE id = ?')->execute([$zzRole]);
    };
    $grant = fn(string $cap) => $conn->prepare('INSERT INTO rbac_role_capabilities (role_id, capability_key) VALUES (?, ?)')->execute([$zzRole, $cap]);
    $conn->prepare('INSERT INTO rbac_analyst_roles (analyst_id, role_id) VALUES (?, ?)')->execute([$nonAdmin, $zzRole]);
    $conn->prepare('UPDATE analysts SET can_access_all_modules = 1 WHERE id = ?')->execute([$nonAdmin]);
    $grant(capKey(Cap::FILES_MANAGE));
    [$code] = $http($userSid);
    ok('"Manage everything in Files" does not open Backups', $code === 403 && $page($userSid) === 302, (string)$code);
    $grant(capKey(Cap::FILES_STORAGE_BACKUPS));
    [$code, $j] = $http($userSid);
    ok('Storage and backups opens the API to a non-administrator', $code === 200 && !empty($j['success']), (string)$code);
    ok('...and the page', $page($userSid) === 200);
    $conn->prepare('UPDATE analysts SET can_access_all_modules = 0 WHERE id = ?')->execute([$nonAdmin]);
    [$code] = $http($userSid);
    ok('...but not without access to Files (the permission is Files\'s)', $code === 403 && $page($userSid) === 302, (string)$code);
    $conn->prepare('UPDATE analysts SET can_access_all_modules = 1 WHERE id = ?')->execute([$nonAdmin]);
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

    // Watchtower's Backups card: only while something is wrong, only for people who can open Backups.
    $wt = function (string $sid) use ($base): string {
        $ch = curl_init($base . 'watchtower/');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_COOKIE => 'PHPSESSID=' . $sid]);
        $b = (string)curl_exec($ch);
        curl_close($ch);
        return $b;
    };
    ok('Watchtower: no Backups card while backups are fine', BackupsService::attention($conn) === [] && !str_contains($wt($adminSid), 'id="wtBackups"'),
       json_encode(BackupsService::attention($conn)));
    $conn->exec("INSERT INTO backup_runs (kind, status, started_at, finished_at, error_text) VALUES ('scheduled', 'failed', UTC_TIMESTAMP(), UTC_TIMESTAMP(), 'ZZ the target is full')");
    $zzFailedRun = (int)$conn->lastInsertId();
    $page = $wt($adminSid);
    ok('Watchtower: the Backups card says the last backup failed', str_contains($page, 'id="wtBackups"') && str_contains($page, 'ZZ the target is full'));
    ok('...to a holder of Storage and backups too', str_contains($wt($userSid), 'id="wtBackups"'));
    $conn->prepare('DELETE FROM rbac_role_capabilities WHERE role_id = ? AND capability_key = ?')->execute([$zzRole, capKey(Cap::FILES_STORAGE_BACKUPS)]);
    ok('...and not to someone who cannot open Backups', !str_contains($wt($userSid), 'id="wtBackups"'));
    $conn->exec("DELETE FROM backup_runs WHERE id = $zzFailedRun");
    BackupsService::saveSchedule($conn, 'off', null, null, 3, $admin);
    section('The backup job');
    ok('the job script exists', is_file("$appRoot/cron/backup.php"));
    BackupsService::saveSchedule($conn, 'daily', null, '03:00', 3, $admin);
    ok('the job is needed once a schedule is set', jobRegistry()['backup']['needed']($conn) === true);
    BackupsService::saveSchedule($conn, 'off', null, null, 3, $admin);

    section('What Watchtower is told (W6, W7)');
    // The history replaced inside a transaction that is rolled back.
    $conn->beginTransaction();
    try {
        $conn->exec('DELETE FROM backup_runs');
        $keys = fn(?int $now = null) => array_column(BackupsService::attention($conn, $now), 'severity', 'key');
        $run = function (string $status, string $ago, ?string $verify = null, ?string $verifiedAgo = null) use ($conn): void {
            $conn->prepare("INSERT INTO backup_runs (kind, status, started_at, finished_at, error_text, verify_status, verified_at)
                            VALUES ('scheduled', ?, UTC_TIMESTAMP() - INTERVAL $ago, UTC_TIMESTAMP() - INTERVAL $ago, ?, ?, "
                            . ($verifiedAgo ? "UTC_TIMESTAMP() - INTERVAL $verifiedAgo" : 'NULL') . ')')
                 ->execute([$status, $status === 'failed' ? 'ZZ broke' : null, $verify]);
        };
        ok('no backups yet and no schedule: nothing to say', $keys() === [], json_encode($keys()));
        $run('ok', '3 DAY', 'ok', '3 DAY');
        $run('ok', '2 HOUR');
        ok('a good, verified history: nothing to say', $keys() === [], json_encode($keys()));
        $run('failed', '1 HOUR');
        ok('the last backup failed: red', ($keys()['last_failed'] ?? null) === 'red', json_encode($keys()));
        $run('ok', '10 MINUTE');
        ok('...and once the next one works, it is gone', !isset($keys()['last_failed']));
        $conn->exec("INSERT INTO backup_runs (kind, status, started_at) VALUES ('manual', 'running', UTC_TIMESTAMP() - INTERVAL 5 MINUTE)");
        ok('a backup that died part way counts as failed', ($keys()['last_failed'] ?? null) === 'red');
        $conn->exec("DELETE FROM backup_runs WHERE status = 'running'");
        BackupsService::saveSchedule($conn, 'daily', null, '03:00', 3, $admin);
        ok('daily, the last backup 10 minutes ago: not overdue', !isset($keys()['overdue']));
        ok('daily, and nothing for more than two days: overdue', ($keys(time() + 3 * 86400)['overdue'] ?? null) === 'red');
        BackupsService::saveSchedule($conn, 'weekly', 3, '03:00', 3, $admin);
        ok('weekly allows eight days', !isset($keys(time() + 5 * 86400)['overdue']) && isset($keys(time() + 9 * 86400)['overdue']));
        $conn->exec('DELETE FROM backup_runs');
        ok('scheduled but never run: overdue once the schedule plus a day has passed since it was set',
           !isset($keys()['overdue']) && isset($keys(time() + 9 * 86400)['overdue']));
        BackupsService::saveSchedule($conn, 'off', null, null, 3, $admin);
        $run('ok', '1 DAY');
        ok('backups never checked with Verify: amber', ($keys()['never_verified'] ?? null) === 'amber', json_encode($keys()));
        $run('ok', '1 HOUR', 'failed', '30 MINUTE');
        ok('the last Verify failed: red', ($keys()['verify_failed'] ?? null) === 'red', json_encode($keys()));
        $run('ok', '20 MINUTE', 'ok', '5 MINUTE');
        ok('...and once a later Verify passes, it is gone', $keys() === [], json_encode($keys()));
        ok('no Verify passed for more than 30 days: amber', ($keys(time() + 31 * 86400)['verify_stale'] ?? null) === 'amber', json_encode($keys(time() + 31 * 86400)));
        $conn->exec("DELETE FROM system_settings WHERE setting_key = 'backup_target'");
        $run('failed', '1 MINUTE');
        ok('an install without backups set up is never told anything', $keys() === []);
    } finally {
        $conn->rollBack();
    }
    ok('mayOpen: an administrator, a holder with Files, nobody else', BackupsService::mayOpen($conn, $admin) && !BackupsService::mayOpen($conn, $nonAdmin));
} catch (Throwable $e) {
    ok('no unexpected error', false, get_class($e) . ': ' . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine());
} finally {
    foreach (array_reverse($cleanup) as $c) { try { $c(); } catch (Throwable $ignored) {} }
    try { $conn->exec("DROP DATABASE IF EXISTS `$restoreDb`"); } catch (Throwable $ignored) {}   // always, whatever happened
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
