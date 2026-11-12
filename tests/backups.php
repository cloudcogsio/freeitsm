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

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
