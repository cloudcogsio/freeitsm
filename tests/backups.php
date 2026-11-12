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

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
