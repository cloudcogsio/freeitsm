<?php
/**
 * The command-line restore (#286): scripts/backup_restore.php hands its arguments here.
 * Rebuilds an install from a backup with nothing but the target and the passphrase.
 *
 * Exit codes: 0 restored, 1 restored with errors (or failed part way), 2 nothing done
 * (usage, refused, wrong passphrase, unreadable backup).
 */

require_once __DIR__ . '/restore.php';
require_once __DIR__ . '/runner.php';

const BACKUP_CLI_USAGE = <<<'TXT'
Restore FreeITSM from a backup made on System -> Backups.

  php scripts/backup_restore.php [target] [options]

Target (asked for when not given):
  --folder=<path>             a folder target (the folder you set; backups are in <path>/backup)
  --s3-endpoint=<url> --s3-bucket=<name> [--s3-region=<r>] [--s3-prefix=<p>] [--s3-path-style] --s3-key=<access key id>
                              an S3-compatible target; the secret comes from FREEITSM_BACKUP_S3_SECRET or is asked for

Options:
  --list                      list the backups on the target and stop
  --set=<name>|latest         which backup (default: asked, offering the newest)
  --force                     restore over a database in use, and replace a different encryption key
  --yes                       do not ask for confirmation
  --database=<name>           restore into this database on the configured server instead of the configured one
  --app-root=<path>           restore upload folders under this folder instead of this install
  --key-path=<path>           write the encryption key here instead of the configured path
  --no-verify-schema          do not run Database Verification afterwards

The passphrase comes from FREEITSM_BACKUP_PASSPHRASE or is asked for (never as an option).
In Docker, start the container with FREEITSM_SCHEDULER=0 until the restore is done, then:
  docker compose exec app php scripts/backup_restore.php

TXT;

/** @return int exit code */
function backupRestoreCli(array $argv, $in = STDIN, $out = STDOUT): int
{
    $say = function (string $s) use ($out) { fwrite($out, $s . "\n"); };
    $known = ['folder', 's3-endpoint', 's3-bucket', 's3-region', 's3-prefix', 's3-path-style', 's3-key', 'list', 'set',
              'force', 'yes', 'database', 'app-root', 'key-path', 'no-verify-schema', 'help'];
    $opt = [];
    foreach (array_slice($argv, 1) as $a) {
        if (!preg_match('/^--([a-z0-9-]+)(?:=(.*))?$/s', $a, $m) || !in_array($m[1], $known, true)) {
            $say("Unknown option: $a\n");
            $say(BACKUP_CLI_USAGE);
            return 2;
        }
        $opt[$m[1]] = $m[2] ?? true;
    }
    if (isset($opt['help'])) { $say(BACKUP_CLI_USAGE); return 0; }
    if (!backupSodiumAvailable()) { $say('This PHP has no sodium extension; backups cannot be read without it.'); return 2; }
    $interactive = function_exists('posix_isatty') ? @posix_isatty($in) : false;
    $ask = function (string $q, bool $hidden = false) use ($in, $out, $interactive): string {
        fwrite($out, $q);
        if ($hidden && $interactive) @shell_exec('stty -echo 2>/dev/null');
        $line = fgets($in);
        if ($hidden && $interactive) { @shell_exec('stty echo 2>/dev/null'); fwrite($out, "\n"); }
        return $line === false ? '' : trim($line);
    };

    // The target.
    if (!isset($opt['folder']) && !isset($opt['s3-endpoint'])) {
        $kind = strtolower($ask('Where are the backups? Type folder or s3: '));
        if ($kind === 'folder') $opt['folder'] = $ask('Folder (the one set on System -> Backups): ');
        elseif ($kind === 's3') {
            $opt['s3-endpoint'] = $ask('Endpoint (https://...): ');
            $opt['s3-bucket']   = $ask('Bucket: ');
            $opt['s3-region']   = $ask('Region (blank for us-east-1): ');
            $opt['s3-prefix']   = $ask('Prefix (blank for none): ');
            $opt['s3-key']      = $ask('Access key ID: ');
            if (strtolower($ask('Path-style addressing? (y/n): ')) === 'y') $opt['s3-path-style'] = true;
        } else { $say('Nothing to restore from.'); return 2; }
    }
    if (isset($opt['folder'])) {
        $cfg = ['type' => 'folder', 'folder' => (string)$opt['folder']];
        if (!is_dir($cfg['folder'] . '/backup')) { $say('No backups found in ' . $cfg['folder'] . ' (expected a "backup" folder inside it).'); return 2; }
    } else {
        $secret = getenv('FREEITSM_BACKUP_S3_SECRET');
        if ($secret === false || $secret === '') $secret = $ask('Secret access key: ', true);
        try {
            $cfg = ['type' => 's3', 'endpoint' => s3NormaliseEndpoint((string)$opt['s3-endpoint']), 'bucket' => (string)($opt['s3-bucket'] ?? ''),
                    'region' => (string)($opt['s3-region'] ?? '') ?: 'us-east-1', 'prefix' => s3NormalisePrefix((string)($opt['s3-prefix'] ?? '')),
                    'access_key_id' => (string)($opt['s3-key'] ?? ''), 'secret' => $secret, 'path_style' => isset($opt['s3-path-style'])];
        } catch (InvalidArgumentException $e) {
            $say($e->getMessage());
            return 2;
        }
    }
    $target = backupTargetDriver($cfg);

    try {
        $sets = array_values(array_filter(backupListSets($target), fn($s) => $s['complete']));
    } catch (Throwable $e) {
        $say('The backup target could not be read: ' . $e->getMessage());
        return 2;
    }
    if (isset($opt['list'])) {
        if (!$sets) $say('No complete backups on this target.');
        foreach ($sets as $s) $say(sprintf('  %s   files %d   %.1f MB', $s['name'], $s['files'], $s['size'] / 1048576));
        return 0;
    }
    if (!$sets) { $say('No complete backups on this target.'); return 2; }
    $set = isset($opt['set']) && $opt['set'] !== true ? (string)$opt['set'] : '';
    if ($set === '' && !isset($opt['yes'])) {
        $say('Backups on this target (newest first):');
        foreach (array_slice($sets, 0, 20) as $s) $say('  ' . $s['name']);
        $set = $ask('Which one? (blank for the newest): ');
    }
    if ($set === '' || $set === 'latest') $set = $sets[0]['name'];
    if (!in_array($set, array_column($sets, 'name'), true)) { $say("There is no complete backup called $set on this target."); return 2; }

    $pass = getenv('FREEITSM_BACKUP_PASSPHRASE');
    if ($pass === false || $pass === '') $pass = $ask('Backup passphrase: ', true);

    // Where it goes.
    $dbName = isset($opt['database']) && $opt['database'] !== true ? (string)$opt['database'] : DB_NAME;
    try {
        $db = new PDO('mysql:host=' . DB_SERVER . ';dbname=' . $dbName . ';charset=utf8mb4', DB_USERNAME, DB_PASSWORD, dbConnectionOptions());
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Throwable $e) {
        $say("The database $dbName could not be opened. Create it (empty) and check the database settings first.");
        return 2;
    }
    if ($dbName !== DB_NAME && (!isset($opt['app-root']) || $opt['app-root'] === true || !isset($opt['key-path']) || $opt['key-path'] === true)) {
        // The in-use and key checks look at the database restored into: aimed at a scratch
        // database, they would let this install's own key and upload folders be overwritten.
        $say('Restoring into another database (--database) also needs --app-root and --key-path, so this install\'s files and key are not touched.');
        return 2;
    }
    $appRoot = isset($opt['app-root']) && $opt['app-root'] !== true ? (string)$opt['app-root'] : dirname(__DIR__, 2);
    $keyPath = isset($opt['key-path']) && $opt['key-path'] !== true ? (string)$opt['key-path']
             : (defined('ENCRYPTION_KEY_PATH') ? (string)ENCRYPTION_KEY_PATH : '');
    if ($keyPath === '') { $say('No encryption key path is configured; give one with --key-path.'); return 2; }

    if (!isset($opt['yes'])) {
        $say("This restores backup $set into database $dbName, the files under $appRoot and the key at $keyPath.");
        $say('Everything now in that database is replaced.');
        if ($ask('Type RESTORE to continue: ') !== 'RESTORE') { $say('Nothing was changed.'); return 2; }
    }

    // A trial restore into another database must not write Files content where the restored
    // settings point: that is the live install's Files storage. It goes under --app-root.
    $filesStore = null;
    if ($dbName !== DB_NAME) {
        $filesStore = new LocalDriver($appRoot . '/uploads/files');
        $say("Files content goes to $appRoot/uploads/files (not to the Files storage the restored settings name).");
    }

    try {
        $br = new BackupRestore($target, $set, $pass, $db, $appRoot, $keyPath, isset($opt['force']), $say, $filesStore);
        // A trial restore into another database keeps every store (#284) under --app-root too,
        // never in the bucket the restored settings name.
        if ($filesStore !== null) $br->storeDriverFor = fn(string $store) => null;
        $r = $br->run();
    } catch (BackupWrongPassphrase $e) {
        $say('That passphrase does not open these backups. Nothing was changed.');
        return 2;
    } catch (BackupRestoreRefused $e) {
        $say($e->getMessage() . ' Nothing was changed.');
        return 2;
    } catch (Throwable $e) {
        $say('The restore stopped: ' . $e->getMessage());
        return 1;
    }
    foreach ($r['warnings'] as $w) $say('Warning: ' . $w);
    foreach ($r['errors'] as $e) $say('Error: ' . $e);

    if (!isset($opt['no-verify-schema'])) {
        if ($dbName !== DB_NAME) {
            $say('Database Verification was not run (it checks the configured database). Run it from System -> Database once this install uses the restored one.');
        } else {
            $say('Running Database Verification...');
            passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__, 2) . '/scripts/db_verify_cli.php') . ' --apply --quiet', $code);
            if ($code !== 0) { $say('Database Verification reported a problem: run it from System -> Database.'); return 1; }
        }
    }
    $say($r['ok'] ? 'Restore complete. Sign in as before.' : 'Restore finished with errors (listed above).');
    return $r['ok'] ? 0 : 1;
}
