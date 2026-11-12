<?php
/**
 * One backup run (#286), and pruning old ones.
 *
 * A run writes one set to the target (see target.php for the layout):
 *
 *   sets/<name>/owner.json     first: which install is writing it (plain, no secrets)
 *   sets/<name>/db.bin         the database dump (dump.php), encrypted with the set's data key
 *   sets/<name>/key.bin        the app's encryption key file, encrypted with the data key
 *   sets/<name>/manifest.bin   JSON: every file (store, path, size, sha256, pool name), table
 *                              counts, the dump's checksum - encrypted with the data key
 *   sets/<name>/datakey.bin    the data key, sealed to the backup public key
 *   sets/<name>/refs.txt       plain: the pool names this set uses (pruning reads it unlocked)
 *   sets/<name>/keyring.json   a copy of the keyring
 *   sets/<name>/done.json      LAST, after the automatic verification: the set is complete
 *
 * Files are pooled: pool/<HMAC(sha256)> holds a file's bytes encrypted under its own
 * key, pool/<name>.key that key sealed to the public key. A file already in the pool
 * at the right size is referenced, not uploaded again - so a run that dies part way
 * loses nothing, and the next one carries on where it stopped.
 *
 * Scheduled runs never see the passphrase: they only seal to the public key.
 */

require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/dump.php';
require_once __DIR__ . '/target.php';
require_once __DIR__ . '/../storage_persistence.php';
require_once __DIR__ . '/../files/storage.php';
require_once __DIR__ . '/../version.php';

final class BackupRunner
{
    /** Upload folders (relative to the app) never backed up: temporary or regenerable. */
    public const SKIP_DIRS = ['uploads/asset-imports', 'recordings/pending'];

    /** Test hook: runs after the inventory is taken, before any file is copied. */
    public ?Closure $afterInventory = null;

    private PDO $conn;
    private StorageDriver&StorageLister $target;
    private string $appRoot;
    private ?Closure $mailer;
    private string $keyPath;
    private string $tmp = '';

    /**
     * @param callable|null $mailer  fn(string $subject, string $body): void - told when a run fails
     *                               (default: every active administrator, by email)
     */
    public function __construct(PDO $conn, StorageDriver&StorageLister $target, string $appRoot,
                                ?callable $mailer = null, ?string $keyPath = null)
    {
        $this->conn    = $conn;
        $this->target  = $target;
        $this->appRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
        $this->mailer  = $mailer !== null ? Closure::fromCallable($mailer) : null;
        $this->keyPath = $keyPath ?? (defined('ENCRYPTION_KEY_PATH') ? (string)ENCRYPTION_KEY_PATH : '');
    }

    /**
     * Takes one backup. Never throws for a failed backup: it is recorded and reported.
     *
     * @param string $kind  scheduled | manual
     * @return array{status: string, run_id: int, set: ?string, files_total: int, files_new: int,
     *               size: int, warning: ?string, error: ?string, prune: ?array}
     */
    public function run(string $kind, ?int $by): array
    {
        if ($this->conn->inTransaction()) {
            throw new LogicException('A backup cannot start inside a transaction: its snapshot would end the caller\'s work.');
        }
        $this->conn->prepare("INSERT INTO backup_runs (kind, status, started_at, started_by) VALUES (?, 'running', UTC_TIMESTAMP(), ?)")
                   ->execute([$kind === 'scheduled' ? 'scheduled' : 'manual', $by]);
        $runId = (int)$this->conn->lastInsertId();
        $out = ['status' => 'failed', 'run_id' => $runId, 'set' => null, 'files_total' => 0, 'files_new' => 0,
                'size' => 0, 'warning' => null, 'error' => null, 'prune' => null];
        $warnings = [];
        $set = null;
        $complete = false;
        $this->seen = [];
        try {
            if (!backupSodiumAvailable()) throw new RuntimeException('This server\'s PHP has no sodium extension, which backups need for encryption.');
            $keyring   = backupKeyring($this->conn);
            $public    = base64_decode(backupSetting($this->conn, 'backup_public_key'), true);
            $installId = backupSetting($this->conn, 'backup_install_id');
            if ($keyring === null || !$public || $installId === '') throw new RuntimeException('No backup passphrase has been set.');
            $poolKey = backupPoolNameKey($this->conn);

            $this->tmp = sys_get_temp_dir() . '/freeitsm-backup-' . bin2hex(random_bytes(6));
            if (!@mkdir($this->tmp, 0700)) throw new RuntimeException('The server\'s temporary folder is not writable.');

            $set = $this->newSetName();
            $out['set'] = $set;
            $this->putString("sets/$set/owner.json", json_encode(['install_id' => $installId, 'started_at' => gmdate('c')]));
            $this->conn->prepare('UPDATE backup_runs SET set_name = ? WHERE id = ?')->execute([$set, $runId]);

            // 1. The database and the list of Files keys, at one moment.
            $dump = $this->tmp . '/db.dump';
            $this->conn->exec('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            $this->conn->beginTransaction();
            try {
                $info = backupDumpDatabase($this->conn, $dump);
                $filesKeys = $this->conn->query('SELECT DISTINCT storage_path FROM files_versions ORDER BY storage_path')->fetchAll(PDO::FETCH_COLUMN);
                $this->conn->commit();
            } catch (Throwable $e) {
                if ($this->conn->inTransaction()) $this->conn->rollBack();
                throw $e;
            }

            // 2. Every other stored file.
            $inventory = [];
            foreach ($filesKeys as $k) $inventory[] = ['store' => 'files', 'path' => (string)$k];
            foreach ($this->directoryFiles() as $f) $inventory[] = $f;
            if ($this->afterInventory) ($this->afterInventory)();

            // 3. Pool every file.
            $dataKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
            $files = [];
            $refs = [];
            $plainTotal = 0;
            foreach ($inventory as $f) {
                $entry = $this->poolFile($f, $poolKey, $public, $out, $warnings);
                $files[] = $entry;
                if (isset($entry['pool'])) {
                    $refs[$entry['pool']] = (int)$entry['size'];
                    $plainTotal += (int)$entry['size'];
                }
            }

            // 4. The set itself.
            $this->putEncrypted("sets/$set/db.bin", $dump, $dataKey);
            $keyFile = $this->keyPath !== '' && is_file($this->keyPath) ? $this->keyPath : null;
            if ($keyFile === null || ($keyBytes = @file_get_contents($keyFile)) === false) {
                throw new RuntimeException('The encryption key file could not be read, so it cannot be backed up.');
            }
            $this->putEncryptedString("sets/$set/key.bin", $keyBytes, $dataKey);
            $manifest = [
                'format'      => 1,
                'app_version' => freeitsmVersion(),
                'created_at'  => gmdate('c'),
                'set'         => $set,
                'install_id'  => $installId,
                'db_name'     => (string)$this->conn->query('SELECT DATABASE()')->fetchColumn(),
                'tables'      => $info['tables'],
                'db'          => ['size' => (int)filesize($dump), 'sha256' => hash_file('sha256', $dump)],
                'key'         => ['size' => strlen($keyBytes), 'sha256' => hash('sha256', $keyBytes)],
                'files'       => $files,
            ];
            $this->putEncryptedString("sets/$set/manifest.bin", json_encode($manifest, JSON_UNESCAPED_SLASHES), $dataKey);
            $this->putString("sets/$set/datakey.bin", backupSealKey($dataKey, $public));
            ksort($refs);
            $this->putString("sets/$set/refs.txt", implode("\n", array_keys($refs)) . ($refs ? "\n" : ''));
            $this->putString("sets/$set/keyring.json", json_encode($keyring, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            sodium_memzero($dataKey);

            // 5. Automatic verification: everything it refers to is there at the expected size.
            foreach (['db.bin', 'key.bin', 'manifest.bin', 'datakey.bin', 'refs.txt', 'keyring.json'] as $o) {
                if ($this->target->size("sets/$set/$o") === null) throw new RuntimeException("The backup's $o is missing from the target after it was written.");
            }
            foreach ($refs as $name => $size) {
                if ($this->target->size("pool/$name") !== backupEncryptedSize($size) || $this->target->size("pool/$name.key") === null) {
                    throw new RuntimeException('A stored file is missing from the backup target, or has the wrong size, after it was written.');
                }
            }
            $this->putString("sets/$set/done.json", json_encode([
                'format' => 1, 'created_at' => gmdate('c'), 'install_id' => $installId,
                'files' => count($refs), 'size' => $plainTotal + (int)filesize($dump),
            ]));
            $complete = true;

            $out['status']  = 'ok';
            $out['size']    = $plainTotal + (int)filesize($dump);
            $out['warning'] = $warnings ? implode("\n", $warnings) : null;
            $this->conn->prepare("UPDATE backup_runs SET status = 'ok', finished_at = UTC_TIMESTAMP(), size_bytes = ?, files_total = ?,
                                         files_new = ?, db_bytes = ?, warning_text = ? WHERE id = ?")
                       ->execute([$out['size'], $out['files_total'], $out['files_new'], (int)filesize($dump), $out['warning'], $runId]);

            // 6. Retention. A failure here does not undo a good backup.
            try {
                $out['prune'] = $this->prune(BackupsKeep::count($this->conn), $installId);
                if ($out['prune']['gc_skipped']) $warnings[] = 'Old stored files were not cleaned up this time: ' . $out['prune']['gc_reason'];
            } catch (Throwable $e) {
                $warnings[] = 'Old backups could not be removed: ' . $e->getMessage();
            }
            if ($warnings && implode("\n", $warnings) !== (string)$out['warning']) {
                $out['warning'] = implode("\n", $warnings);
                $this->conn->prepare('UPDATE backup_runs SET warning_text = ? WHERE id = ?')->execute([$out['warning'], $runId]);
            }
        } catch (Throwable $e) {
            $out['status'] = 'failed';
            $out['error']  = self::cleanError($e);
            if ($this->conn->inTransaction()) $this->conn->rollBack();
            try {
                $this->conn->prepare("UPDATE backup_runs SET status = 'failed', finished_at = UTC_TIMESTAMP(), files_total = ?, files_new = ?,
                                             error_text = ?, warning_text = ? WHERE id = ?")
                           ->execute([$out['files_total'], $out['files_new'], $out['error'], $warnings ? implode("\n", $warnings) : null, $runId]);
            } catch (Throwable $ignored) {
                // the job run record still says it failed
            }
            if ($set !== null && !$complete) $this->removeSet($set);
            $this->notify($out['error']);
        } finally {
            if ($this->tmp !== '') self::rmTree($this->tmp);
            $this->tmp = '';
        }
        return $out;
    }

    /**
     * Removes sets beyond the newest $keep complete ones of this install, this install's
     * incomplete sets (a run holding the lock means none of them is still being written),
     * then every pool object no remaining set references.
     *
     * The pool clean-up reads every remaining set's refs.txt FROM THE TARGET, so it is
     * right after a restore or with two installs on one target. Any doubt skips it.
     *
     * @return array{sets_removed: int, pool_removed: int, gc_skipped: bool, gc_reason: ?string}
     */
    public function prune(int $keep, string $installId): array
    {
        $sets = [];
        foreach ($this->target->listKeys('sets/') as $k) {
            $parts = explode('/', $k, 3);
            if (count($parts) === 3) $sets[$parts[1]][$parts[2]] = true;
        }
        $mine = [];
        $removed = 0;
        $gcSkip = null;
        foreach ($sets as $name => $objs) {
            $owner = isset($objs['done.json']) ? $this->readJson("sets/$name/done.json")
                   : (isset($objs['owner.json']) ? $this->readJson("sets/$name/owner.json") : null);
            $ownerId = is_array($owner) ? (string)($owner['install_id'] ?? '') : '';
            if ($ownerId !== $installId) {
                // Another install's set: leave it. One still being written may hold pool
                // objects it has not listed yet, so the pool is left alone too.
                if (!isset($objs['done.json']) && !isset($objs['refs.txt'])) $gcSkip = 'another install is writing a backup to this target.';
                continue;
            }
            if (isset($objs['done.json'])) {
                $mine[] = $name;
            } else {
                $this->removeSet($name, array_keys($objs));
                $removed++;
                unset($sets[$name]);
            }
        }
        rsort($mine, SORT_STRING);
        foreach (array_slice($mine, max(1, $keep)) as $name) {
            $this->removeSet($name, array_keys($sets[$name]));
            $removed++;
            unset($sets[$name]);
        }

        $poolRemoved = 0;
        if ($gcSkip === null) {
            $used = [];
            try {
                foreach ($sets as $name => $objs) {
                    if (!isset($objs['refs.txt'])) {
                        // A complete set always has one: without it, what it uses is unknown.
                        if (isset($objs['done.json'])) throw new RuntimeException('missing refs.txt');
                        continue;
                    }
                    foreach (explode("\n", $this->readString("sets/$name/refs.txt")) as $n) {
                        $n = trim($n);
                        if ($n !== '') $used[$n] = true;
                    }
                }
            } catch (Throwable $e) {
                $gcSkip = 'a backup\'s list of stored files could not be read.';
            }
            if ($gcSkip === null) {
                foreach ($this->target->listKeys('pool/') as $k) {
                    $name = preg_replace('/\.key$/', '', substr($k, 5));
                    if (isset($used[$name])) continue;
                    $this->target->delete($k);
                    if (!str_ends_with($k, '.key')) $poolRemoved++;
                }
            }
        }
        return ['sets_removed' => $removed, 'pool_removed' => $poolRemoved, 'gc_skipped' => $gcSkip !== null, 'gc_reason' => $gcSkip];
    }

    // ── internals ──

    /** Every file in the upload folders, as ['store' => 'dir:<rel>', 'path' => ...]. */
    private function directoryFiles(): array
    {
        $skip = array_map(fn($d) => $this->appRoot . '/' . $d, self::SKIP_DIRS);
        $filesRoot = rtrim(str_replace('\\', '/', filesStorageRoot($this->conn)), '/');
        $skip[] = $filesRoot;
        $out = [];
        foreach (storagePersistenceDirectories() as $d) {
            if (!empty($d['critical'])) continue;   // the key: backed up on its own
            $rel  = (string)$d['rel'];
            $base = $this->appRoot . '/' . $rel;
            if (!is_dir($base)) continue;
            $it = new RecursiveIteratorIterator(
                new RecursiveCallbackFilterIterator(
                    new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                    function (SplFileInfo $f) use ($skip) {
                        $p = rtrim(str_replace('\\', '/', $f->getPathname()), '/');
                        foreach ($skip as $s) if ($p === $s || str_starts_with($p, $s . '/')) return false;
                        return !$f->isLink();
                    }),
                RecursiveIteratorIterator::LEAVES_ONLY);
            foreach ($it as $f) {
                if (!$f->isFile()) continue;
                $p = str_replace('\\', '/', $f->getPathname());
                $out[] = ['store' => 'dir:' . $rel, 'path' => substr($p, strlen($base) + 1)];
            }
        }
        usort($out, fn($a, $b) => [$a['store'], $a['path']] <=> [$b['store'], $b['path']]);
        return $out;
    }

    /** Puts one file in the pool (or finds it there) and returns its manifest entry. */
    private function poolFile(array $f, string $poolKey, string $public, array &$out, array &$warnings): array
    {
        $local = null;
        $copy  = null;
        if ($f['store'] === 'files') {
            $copy = $this->tmp . '/file.bin';
            try {
                filesStoreFor($this->conn, $f['path'])->readTo($f['path'], $copy);
            } catch (StorageNotFound $e) {
                $st = $this->conn->prepare('SELECT 1 FROM files_versions WHERE storage_path = ? LIMIT 1');
                $st->execute([$f['path']]);
                if ($st->fetchColumn()) throw new RuntimeException('A file in Files is missing from Files storage: ' . $f['path']);
                $warnings[] = 'A file in Files was deleted while the backup ran and is not in it: ' . $f['path'];
                return $f + ['missing' => 'deleted during backup'];
            } catch (StorageUnavailable $e) {
                throw new RuntimeException('Files storage could not be read: ' . $e->getMessage());
            }
            $local = $copy;
        } else {
            $local = $this->appRoot . '/' . substr($f['store'], 4) . '/' . $f['path'];
        }
        $sha = @hash_file('sha256', $local);
        $size = @filesize($local);
        if ($sha === false || $size === false) {
            throw new RuntimeException('A stored file could not be read: ' . substr($f['store'], 4) . '/' . $f['path']);
        }
        $name = backupPoolName($poolKey, $sha);
        $out['files_total']++;
        if (!isset($this->seen[$name])) {
            $this->seen[$name] = true;
            if ($this->target->size("pool/$name") !== backupEncryptedSize((int)$size) || $this->target->size("pool/$name.key") === null) {
                $fileKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
                $this->putEncrypted("pool/$name", $local, $fileKey);
                $this->putString("pool/$name.key", backupSealKey($fileKey, $public));
                sodium_memzero($fileKey);
                $out['files_new']++;
            }
        }
        if ($copy !== null) @unlink($copy);
        return $f + ['size' => (int)$size, 'sha256' => $sha, 'pool' => $name];
    }

    /** @var array<string,bool> pool names handled in this run */
    private array $seen = [];

    private function newSetName(): string
    {
        for ($i = 0; $i < 5; $i++) {
            $name = gmdate('Ymd\THis\Z');
            if (!$this->target->listKeys("sets/$name/")) return $name;
            sleep(1);
        }
        throw new RuntimeException('Could not choose a name for the backup.');
    }

    private function putEncrypted(string $key, string $plainPath, string $encKey): void
    {
        $enc = $this->tmp . '/enc.bin';
        try {
            backupEncryptFile($plainPath, $enc, $encKey);
            $this->target->putFile($key, $enc);
        } finally {
            @unlink($enc);
        }
    }

    private function putEncryptedString(string $key, string $plain, string $encKey): void
    {
        $p = $this->tmp . '/plain.bin';
        try {
            if (file_put_contents($p, $plain) === false) throw new RuntimeException('The server\'s temporary folder is not writable.');
            $this->putEncrypted($key, $p, $encKey);
        } finally {
            @unlink($p);
        }
    }

    private function putString(string $key, string $data): void
    {
        $p = ($this->tmp !== '' ? $this->tmp : sys_get_temp_dir()) . '/put-' . bin2hex(random_bytes(4));
        try {
            if (file_put_contents($p, $data) === false) throw new RuntimeException('The server\'s temporary folder is not writable.');
            $this->target->putFile($key, $p);
        } finally {
            @unlink($p);
        }
    }

    private function readString(string $key): string
    {
        $p = sys_get_temp_dir() . '/bkread-' . bin2hex(random_bytes(6));
        try {
            $this->target->readTo($key, $p);
            $s = @file_get_contents($p);
            if ($s === false) throw new StorageUnavailable('A backup file could not be read.');
            return $s;
        } finally {
            @unlink($p);
        }
    }

    private function readJson(string $key): ?array
    {
        try {
            $j = json_decode($this->readString($key), true);
            return is_array($j) ? $j : null;
        } catch (StorageNotFound $e) {
            return null;
        }
    }

    /** Deletes a set: done.json first (so a half-deleted set is "incomplete"), owner.json last. */
    private function removeSet(string $name, ?array $objs = null): void
    {
        try {
            $objs ??= array_map(fn($k) => substr($k, strlen("sets/$name/")), $this->target->listKeys("sets/$name/"));
            usort($objs, fn($a, $b) => ($a === 'done.json' ? -1 : ($a === 'owner.json' ? 1 : 0)) <=> ($b === 'done.json' ? -1 : ($b === 'owner.json' ? 1 : 0)));
            foreach ($objs as $o) $this->target->delete("sets/$name/$o");
        } catch (Throwable $e) {
            // the next prune tries again
        }
    }

    private function notify(string $error): void
    {
        try {
            if ($this->mailer) {
                ($this->mailer)('FreeITSM backup failed', $error);
                return;
            }
            backupMailAdmins($this->conn, 'FreeITSM backup failed',
                '<p>A backup did not complete.</p><p>' . htmlspecialchars($error) . '</p><p>See System &rarr; Backups for details.</p>');
        } catch (Throwable $e) {
            // the run is still recorded as failed on the page and in Background jobs
        }
    }

    /** Our own message; never a database or library dump. */
    private static function cleanError(Throwable $e): string
    {
        if ($e instanceof PDOException) return 'A database error stopped the backup.';
        return mb_substr(trim($e->getMessage()), 0, 1000) ?: 'The backup failed.';
    }

    public static function rmTree(string $d): void
    {
        if (!is_dir($d)) return;
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS),
                                               RecursiveIteratorIterator::CHILD_FIRST) as $f) {
            $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($d);
    }
}

/** The keep count, without loading the service (the job needs only this). */
final class BackupsKeep
{
    public static function count(PDO $conn): int
    {
        $k = (int)backupSetting($conn, 'backup_keep_count', '7');
        return $k >= 1 && $k <= 365 ? $k : 7;
    }
}

/** Emails every active administrator through the first mailbox that can send. */
function backupMailAdmins(PDO $conn, string $subject, string $html): int
{
    require_once __DIR__ . '/../self_service_email.php';
    $sent = 0;
    $rows = $conn->query("SELECT email FROM analysts WHERE is_admin = 1 AND is_active = 1 AND email IS NOT NULL AND email <> ''")->fetchAll(PDO::FETCH_COLUMN);
    foreach ($rows as $email) {
        try {
            if (ssSendSystemEmail($conn, (string)$email, $subject, $html, 'backup')) $sent++;
        } catch (Throwable $e) {
            // one bad address does not stop the others
        }
    }
    return $sent;
}
