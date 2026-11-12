<?php
/**
 * Reading backups back (#286): listing the sets on a target, opening one with the
 * passphrase, verifying it, and restoring it (BackupRestore, used by
 * scripts/backup_restore.php).
 */

require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/dump.php';
require_once __DIR__ . '/target.php';
require_once __DIR__ . '/runner.php';

/**
 * The sets on a target, newest first.
 *
 * @return array<int, array{name: string, complete: bool, install_id: ?string, size: ?int, files: ?int, created_at: ?string}>
 */
function backupListSets(StorageDriver&StorageLister $t): array
{
    $sets = [];
    foreach ($t->listKeys('sets/') as $k) {
        $parts = explode('/', $k, 3);
        if (count($parts) === 3) $sets[$parts[1]][$parts[2]] = true;
    }
    krsort($sets, SORT_STRING);
    $out = [];
    foreach ($sets as $name => $objs) {
        $done = isset($objs['done.json']) ? backupReadJson($t, "sets/$name/done.json") : null;
        $out[] = [
            'name'       => (string)$name,
            'complete'   => is_array($done),
            'install_id' => is_array($done) ? (string)($done['install_id'] ?? '') : null,
            'size'       => is_array($done) ? (int)($done['size'] ?? 0) : null,
            'files'      => is_array($done) ? (int)($done['files'] ?? 0) : null,
            'created_at' => is_array($done) ? (string)($done['created_at'] ?? '') : null,
        ];
    }
    return $out;
}

/**
 * Opens a complete set with the passphrase.
 *
 * @return array{keys: array, datakey: string, manifest: array}
 * @throws BackupWrongPassphrase|BackupCorrupt|StorageUnavailable|RuntimeException
 */
function backupOpenSet(StorageDriver&StorageLister $t, string $set, string $passphrase): array
{
    if (!preg_match('/^\d{8}T\d{6}Z$/', $set)) throw new InvalidArgumentException('That is not a backup name.');
    if ($t->size("sets/$set/done.json") === null) throw new RuntimeException("Backup $set is not complete (or does not exist).");
    $datakeyBin  = backupReadString($t, "sets/$set/datakey.bin");
    $manifestBin = backupReadString($t, "sets/$set/manifest.bin");
    $auth        = trim(backupReadString($t, "sets/$set/auth.txt"));

    // The keyring at the target (current passphrase), the set's own copy (the keyring it
    // was made with), then any older keyrings kept beside a newer one.
    $candidates = ['keyring.json', "sets/$set/keyring.json"];
    foreach ($t->listKeys('keyring-') as $k) if (preg_match('/^keyring-[0-9a-f]{16}\.json$/', $k)) $candidates[] = $k;
    $unlocked = false;
    foreach ($candidates as $c) {
        try {
            $kr = backupReadJson($t, $c);
            if (!is_array($kr)) continue;
            $keys = backupUnlockKeyring($kr, $passphrase);
        } catch (BackupWrongPassphrase $e) {
            continue;
        } catch (Throwable $e) {
            continue;   // missing or unreadable: try the next
        }
        $unlocked = true;
        try {
            $dataKey = backupOpenKey($datakeyBin, $keys['public'], $keys['secret']);
        } catch (BackupCorrupt $e) {
            sodium_memzero($keys['secret']);
            continue;   // this passphrase opens a keyring, but not the one this set was made with
        }
        if (!hash_equals(backupSetAuth($keys['pool_name_key'], $set, $datakeyBin, $manifestBin), $auth)) {
            throw new BackupCorrupt("Backup $set is not authentic: it was not made by an install holding this backup's keys.");
        }
        $manifest = json_decode(backupDecryptString($manifestBin, $dataKey), true);
        if (!is_array($manifest) || (int)($manifest['format'] ?? 0) !== 1) throw new BackupCorrupt('The backup manifest is not readable.');
        return ['keys' => $keys, 'datakey' => $dataKey, 'manifest' => $manifest];
    }
    if ($unlocked) throw new BackupCorrupt("Backup $set could not be opened with any keyring this passphrase unlocks.");
    throw new BackupWrongPassphrase('The backup passphrase is not correct.');
}

/** Restore writes upload files only into the folders FreeITSM keeps them in. */
function backupRestoreDirAllowed(string $rel): bool
{
    foreach (storagePersistenceDirectories() as $d) {
        if (empty($d['critical']) && (string)$d['rel'] === $rel) return true;
    }
    return false;
}

/** The whole object as a string (small objects only). */
function backupReadString(StorageDriver $t, string $key): string
{
    $p = sys_get_temp_dir() . '/bkread-' . bin2hex(random_bytes(6));
    try {
        $t->readTo($key, $p);
        $s = @file_get_contents($p);
        if ($s === false) throw new StorageUnavailable('A backup file could not be read.');
        return $s;
    } finally {
        @unlink($p);
    }
}

/** @throws StorageNotFound when it does not exist */
function backupReadJson(StorageDriver $t, string $key): ?array
{
    $j = json_decode(backupReadString($t, $key), true);
    return is_array($j) ? $j : null;
}

/**
 * Decrypts every part of a set and checks every checksum, writing nothing.
 *
 * @return array{ok: bool, checked: int, errors: string[]}
 * @throws BackupWrongPassphrase  (anything wrong with the backup itself is an error in the result)
 */
function backupVerifySet(StorageDriver&StorageLister $t, string $set, string $passphrase): array
{
    $errors = [];
    $checked = 0;
    try {
        $open = backupOpenSet($t, $set, $passphrase);
    } catch (BackupWrongPassphrase $e) {
        throw $e;
    } catch (Throwable $e) {
        return ['ok' => false, 'checked' => 0, 'errors' => [$e->getMessage()]];
    }
    $m = $open['manifest'];
    $tmp = sys_get_temp_dir() . '/bkverify-' . bin2hex(random_bytes(6));
    try {
        foreach (['db.bin' => $m['db'] ?? null, 'key.bin' => $m['key'] ?? null] as $obj => $want) {
            try {
                $t->readTo("sets/$set/$obj", $tmp);
                $sha = backupDecryptFile($tmp, null, $open['datakey']);
                if (!is_array($want) || $sha !== ($want['sha256'] ?? '')) $errors[] = "$obj: the checksum does not match.";
            } catch (Throwable $e) {
                $errors[] = "$obj: " . $e->getMessage();
            }
            $checked++;
        }
        $done = [];
        foreach ((array)($m['files'] ?? []) as $f) {
            if (!isset($f['pool'])) continue;            // recorded as missing when the backup ran
            $label = $f['store'] . ': ' . $f['path'];
            if (!isset($done[$f['pool']])) {
                try {
                    $fk = backupOpenKey(backupReadString($t, 'pool/' . $f['pool'] . '.key'), $open['keys']['public'], $open['keys']['secret']);
                    $t->readTo('pool/' . $f['pool'], $tmp);
                    $sha = backupDecryptFile($tmp, null, $fk);
                    $done[$f['pool']] = $sha === $f['sha256'] ? true : 'the checksum does not match.';
                } catch (Throwable $e) {
                    $done[$f['pool']] = $e->getMessage();
                }
                $checked++;
            }
            if ($done[$f['pool']] !== true) $errors[] = "$label: " . $done[$f['pool']];
        }
    } finally {
        @unlink($tmp);
        sodium_memzero($open['keys']['secret']);
    }
    return ['ok' => !$errors, 'checked' => $checked, 'errors' => $errors];
}

/** The restore will not run without --force (an install in use, or a key it would replace). */
class BackupRestoreRefused extends RuntimeException {}

/**
 * Restores one backup set: the encryption key, the database, every stored file.
 *
 * Refuses (BackupRestoreRefused), before writing anything, when the database is in use
 * (more than one analyst, or anyone has signed in) or an existing, different key would be
 * replaced on an install that may need it - unless $force. A fresh install (the seed admin
 * only, never signed in, no encrypted settings) needs no force: its key protects nothing.
 *
 * Afterwards backups are paused (schedule off) and the install has a new install id, so a
 * trial restore can never prune the original install's backups.
 */
final class BackupRestore
{
    private array $result = ['ok' => false, 'restored_files' => 0, 'skipped_files' => 0, 'warnings' => [], 'errors' => []];
    private string $tmp = '';
    private StorageDriver&StorageLister $t;
    private string $set;
    private string $passphrase;
    private PDO $db;
    private string $appRoot;
    private string $keyPath;
    private bool $force;
    private Closure $log;
    private ?StorageDriver $filesStore;

    /**
     * @param callable           $log         fn(string $line): void - progress for the person running it
     * @param StorageDriver|null $filesStore  where Files bytes go; default: as the RESTORED settings say
     */
    public function __construct(StorageDriver&StorageLister $t, string $set, string $passphrase, PDO $db, string $appRoot,
                                string $keyPath, bool $force, callable $log, ?StorageDriver $filesStore = null)
    {
        $this->t = $t;
        $this->set = $set;
        $this->passphrase = $passphrase;
        $this->db = $db;
        $this->appRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
        $this->keyPath = $keyPath;
        $this->force = $force;
        $this->log = Closure::fromCallable($log);
        $this->filesStore = $filesStore;
    }

    /** @return array{ok: bool, restored_files: int, skipped_files: int, warnings: string[], errors: string[]} */
    public function run(): array
    {
        $open = backupOpenSet($this->t, $this->set, $this->passphrase);
        $m = $open['manifest'];
        ($this->log)("Backup {$this->set}: FreeITSM " . ($m['app_version'] ?? '?') . ', files ' . count((array)$m['files']) . '.');

        $this->tmp = sys_get_temp_dir() . '/freeitsm-restore-' . bin2hex(random_bytes(6));
        if (!@mkdir($this->tmp, 0700)) throw new RuntimeException('The server\'s temporary folder is not writable.');
        try {
            // Everything that can refuse, before anything is written.
            $this->t->readTo("sets/{$this->set}/key.bin", $this->tmp . '/key.enc');
            $keyBytes = backupDecryptString((string)file_get_contents($this->tmp . '/key.enc'), $open['datakey']);
            if (hash('sha256', $keyBytes) !== ($m['key']['sha256'] ?? '')) throw new BackupCorrupt('The backed-up encryption key does not match its checksum.');
            $inUse = $this->databaseInUse();
            if ($inUse && !$this->force) {
                throw new BackupRestoreRefused('This database is in use (it has analysts who have signed in). A restore replaces everything in it: run again with --force if that is what you want.');
            }
            $existing = is_file($this->keyPath) ? trim((string)@file_get_contents($this->keyPath)) : null;
            $keyDiffers = $existing !== null && $existing !== trim($keyBytes);
            if ($keyDiffers && !$this->force && ($inUse || $this->hasEncryptedSettings())) {
                throw new BackupRestoreRefused('A different encryption key is already at ' . $this->keyPath . ' and this install may need it. Run again with --force to replace it.');
            }

            // The database.
            $this->t->readTo("sets/{$this->set}/db.bin", $this->tmp . '/db.enc');
            $sha = backupDecryptFile($this->tmp . '/db.enc', $this->tmp . '/db.dump', $open['datakey']);
            @unlink($this->tmp . '/db.enc');
            if ($sha !== ($m['db']['sha256'] ?? '')) throw new BackupCorrupt('The database dump does not match its checksum.');
            ($this->log)('Restoring the database...');
            $this->dropEverything();
            $n = backupReplayDump($this->db, $this->tmp . '/db.dump');
            @unlink($this->tmp . '/db.dump');
            ($this->log)("Database restored ($n statements).");
            $this->afterDatabase();

            // The key.
            if ($existing === null || $keyDiffers) {
                $this->writeFile($this->keyPath, 0600, $keyBytes);
                ($this->log)('Encryption key restored to ' . $this->keyPath . '.');
            }

            // Every stored file.
            $files = $this->filesStore ?? $this->restoredFilesStore(trim($keyBytes));
            $this->restoreFiles($m, $open['keys'], $files);
            $this->rewriteRfpPaths();
        } finally {
            sodium_memzero($open['keys']['secret']);
            BackupRunner::rmTree($this->tmp);
        }
        $this->result['ok'] = !$this->result['errors'];
        return $this->result;
    }

    // ── steps ──

    private function databaseInUse(): bool
    {
        try {
            $n = (int)$this->db->query('SELECT COUNT(*) FROM analysts')->fetchColumn();
            if ($n === 0) return false;
            if ($n > 1) return true;
            return (int)$this->db->query('SELECT COUNT(*) FROM analysts WHERE last_login_datetime IS NOT NULL')->fetchColumn() > 0;
        } catch (PDOException $e) {
            if ($e->getCode() === '42S02') return false;   // no analysts table: an empty database
            throw $e;                                       // anything else: do not guess
        }
    }

    private function hasEncryptedSettings(): bool
    {
        try {
            return (int)$this->db->query("SELECT COUNT(*) FROM system_settings WHERE setting_value LIKE 'ENC:%'")->fetchColumn() > 0;
        } catch (PDOException $e) {
            if ($e->getCode() === '42S02') return false;
            throw $e;
        }
    }

    private function dropEverything(): void
    {
        $this->db->exec('SET FOREIGN_KEY_CHECKS = 0');
        foreach ($this->db->query('SHOW FULL TABLES')->fetchAll(PDO::FETCH_NUM) as $r) {
            $this->db->exec(($r[1] === 'VIEW' ? 'DROP VIEW IF EXISTS ' : 'DROP TABLE IF EXISTS ') . backupIdent((string)$r[0]));
        }
        $this->db->exec('SET FOREIGN_KEY_CHECKS = 1');
    }

    /** Backups paused and a new install id: the restored install must not prune the original's sets. */
    private function afterDatabase(): void
    {
        $set = $this->db->prepare('INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)
                                    ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)');
        $set->execute(['backup_schedule', 'off']);
        $set->execute(['backup_install_id', bin2hex(random_bytes(16))]);
        $this->db->exec("DELETE FROM system_settings WHERE setting_key = 'backup_install_fingerprint'");   // recorded by its first backup
        try {
            $this->db->exec("UPDATE job_schedules SET mode = 'off', next_due_at = NULL WHERE job_key = 'backup'");
        } catch (PDOException $e) {
            // an older backup without the scheduler table: Database Verification creates it
        }
        ($this->log)('Scheduled backups are paused on this install: turn them back on in System -> Backups.');
    }

    /** The Files store as the restored settings describe it (its secret read with the restored key). */
    private function restoredFilesStore(string $keyHex): StorageDriver
    {
        $get = function (string $k, string $d = ''): string {
            $s = $this->db->prepare('SELECT setting_value FROM system_settings WHERE setting_key = ?');
            $s->execute([$k]);
            $v = $s->fetchColumn();
            return $v === false || $v === null ? $d : (string)$v;
        };
        if ($get('files_storage_driver', 'local') === 's3') {
            return storageDriver([
                'driver' => 's3', 'endpoint' => $get('files_s3_endpoint'), 'region' => $get('files_s3_region', 'us-east-1'),
                'bucket' => $get('files_s3_bucket'), 'access_key_id' => $get('files_s3_access_key_id'),
                'secret' => backupDecryptWithKey($get('files_s3_secret'), $keyHex),
                'prefix' => $get('files_s3_prefix'), 'path_style' => $get('files_s3_path_style', '0') === '1',
            ], 'files');
        }
        $root = $get('files_storage_root');
        return new LocalDriver($root !== '' ? $root : $this->appRoot . '/uploads/files');
    }

    private function restoreFiles(array $m, array $keys, StorageDriver $files): void
    {
        $total = count((array)$m['files']);
        $i = 0;
        foreach ((array)$m['files'] as $f) {
            $i++;
            $label = $f['store'] . ': ' . $f['path'];
            if (!isset($f['pool'])) {
                $this->result['warnings'][] = "$label was deleted while the backup ran, so it is not in the backup.";
                continue;
            }
            try {
                if ($f['store'] === 'files') {
                    if ($files->size($f['path']) === (int)$f['size']) { $this->result['skipped_files']++; continue; }
                    $files->putFile($f['path'], $this->fetch($f, $keys), true);
                } elseif (str_starts_with($f['store'], 'dir:')) {
                    $rel = substr($f['store'], 4);
                    if (!backupRestoreDirAllowed($rel) || str_contains($f['path'], '..') || $f['path'] === '' || $f['path'][0] === '/' || str_contains($f['path'], "\0")) {
                        throw new RuntimeException('an unsafe path in the manifest');
                    }
                    $dest = $this->appRoot . '/' . $rel . '/' . $f['path'];
                    if (is_file($dest) && hash_file('sha256', $dest) === $f['sha256']) { $this->result['skipped_files']++; continue; }
                    $this->writeFile($dest, 0640, null, $this->fetch($f, $keys));
                } else {
                    throw new RuntimeException('an unknown store');
                }
                $this->result['restored_files']++;
            } catch (Throwable $e) {
                $this->result['errors'][] = "$label: " . $e->getMessage();
            }
            if ($i % 500 === 0) ($this->log)("Files: $i of $total");
        }
        ($this->log)("Files restored: {$this->result['restored_files']}, already there: {$this->result['skipped_files']}, failed: " . count($this->result['errors']) . '.');
    }

    /** One pooled file, decrypted to a temp file whose checksum has been checked. */
    private function fetch(array $f, array $keys): string
    {
        $fk = backupOpenKey(backupReadString($this->t, 'pool/' . $f['pool'] . '.key'), $keys['public'], $keys['secret']);
        $enc = $this->tmp . '/pool.enc';
        $out = $this->tmp . '/pool.plain';
        $this->t->readTo('pool/' . $f['pool'], $enc);
        $sha = backupDecryptFile($enc, $out, $fk);
        @unlink($enc);
        if ($sha !== $f['sha256']) throw new BackupCorrupt('the checksum does not match.');
        return $out;
    }

    /** Writes $bytes (or moves $fromPath) to $dest through a temp name; owned like its folder when run as root. */
    private function writeFile(string $dest, int $mode, ?string $bytes, ?string $fromPath = null): void
    {
        $dir = dirname($dest);
        if (!is_dir($dir) && !@mkdir($dir, $mode === 0600 ? 0700 : 0750, true) && !is_dir($dir)) {
            throw new RuntimeException("the folder $dir could not be created");
        }
        $tmp = $dest . '.restoring';
        $ok = $fromPath !== null ? (@rename($fromPath, $tmp) || @copy($fromPath, $tmp))
                                 : @file_put_contents($tmp, (string)$bytes) !== false;
        if ($fromPath !== null) @unlink($fromPath);
        if (!$ok || !@rename($tmp, $dest)) {
            @unlink($tmp);
            throw new RuntimeException("$dest could not be written");
        }
        @chmod($dest, $mode);
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            // Run as root (docker compose exec): give it to whoever owns the nearest folder that already existed.
            $probe = $dir;
            while (((int)@fileowner($probe)) === 0 && $probe !== dirname($probe)) $probe = dirname($probe);
            $owner = (int)@fileowner($probe);
            $group = (int)@filegroup($probe);
            if ($owner > 0) {
                for ($d = $dir; strlen($d) > strlen($probe); $d = dirname($d)) { @chown($d, $owner); @chgrp($d, $group); }
                @chown($dest, $owner);
                @chgrp($dest, $group);
            }
        }
    }

    /** RFP documents store absolute paths: point them at this install. */
    private function rewriteRfpPaths(): void
    {
        try {
            $rows = $this->db->query("SELECT id, file_path FROM rfp_documents WHERE file_path LIKE '%/contracts/rfp-builder/uploads/%'")->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            if ($e->getCode() === '42S02') return;   // no such table in this backup
            throw $e;
        }
        $upd = $this->db->prepare('UPDATE rfp_documents SET file_path = ? WHERE id = ?');
        foreach ($rows as $r) {
            $p = str_replace('\\', '/', (string)$r['file_path']);
            $upd->execute([$this->appRoot . '/' . substr($p, strpos($p, '/contracts/rfp-builder/uploads/') + 1), $r['id']]);
        }
    }
}

/** An ENC: setting decrypted with a given key (the restored one, not this process's cached key). */
function backupDecryptWithKey(string $value, string $keyHex): string
{
    if (!str_starts_with($value, 'ENC:')) return $value;
    $raw = base64_decode(substr($value, 4), true);
    $key = @hex2bin($keyHex);
    if ($raw === false || $key === false || strlen($key) !== 32 || strlen($raw) < 29) return '';
    $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $plain === false ? '' : $plain;
}
