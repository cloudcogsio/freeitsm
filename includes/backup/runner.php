<?php
/**
 * One backup run (#286), and pruning old ones.
 *
 * A run writes one set to the target (see target.php for the layout):
 *
 *   sets/<name>/owner.json     first: which install is writing it (plain, no secrets)
 *   sets/<name>/db.bin         the database dump (dump.php), encrypted with the set's data key
 *   sets/<name>/key.bin        the app's encryption key file, encrypted with the data key
 *   sets/<name>/manifest.bin   a JSON header line (table counts, the dump's checksum...), then one
 *                              JSON line per file (store, path, size, sha256, pool name) - encrypted
 *                              with the data key, and written and read as a stream
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
require_once __DIR__ . '/notify.php';
require_once __DIR__ . '/../storage_persistence.php';
require_once __DIR__ . '/../file_stores.php';
require_once __DIR__ . '/../files/storage.php';
require_once __DIR__ . '/../version.php';

/** The manifest's layout: a header line (JSON), then one line per file. Restore and Verify stream it. */
const BACKUP_MANIFEST_FORMAT = 2;

final class BackupRunner
{
    /** Upload folders (relative to the app) never backed up: temporary or regenerable. */
    public const SKIP_DIRS = ['uploads/asset-imports', 'recordings/pending'];

    /** Test hook: runs after the inventory is taken, before any file is copied. */
    public ?Closure $afterInventory = null;

    /** Test hook: fn(string $localPath) - runs after a file's checksum, just before it is encrypted. */
    public ?Closure $beforeEncrypt = null;

    /**
     * How many reused pool objects each run reads back (a random sample). Reuse trusts the listed size;
     * the sample catches an object damaged in place. Verify, with the passphrase, reads everything.
     */
    public int $sampleSize = 5;

    /** Damaged pool objects moved aside by the sample check are removed after this many days. */
    public const QUARANTINE_DAYS = 30;

    /** Unreferenced pool objects younger than this are kept: another run may be about to use them. */
    public int $gcGraceSeconds = 172800;

    /** This install's incomplete sets older than this are abandoned (a run that died) and removed. */
    public int $incompleteMaxAge = 86400;

    private PDO $conn;
    private StorageDriver&StorageLister $target;
    private string $appRoot;
    private ?Closure $mailer;
    private string $keyPath;
    private string $tmp = '';

    /**
     * @param callable|null $mailer  fn(string $subject, string $body): void - told when a run fails
     *                               (default: a bell and an email to the people concerned, backupNotify())
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
        $out = ['status' => 'failed', 'run_id' => 0, 'set' => null, 'files_total' => 0, 'files_new' => 0,
                'size' => 0, 'warning' => null, 'error' => null, 'prune' => null];
        try {
            // A first backup's file phase can take hours with this connection idle: keep it open.
            if ((int)$this->conn->query('SELECT @@SESSION.wait_timeout')->fetchColumn() < 86400) $this->conn->exec('SET SESSION wait_timeout = 86400');
            $this->conn->prepare("INSERT INTO backup_runs (kind, status, started_at, started_by) VALUES (?, 'running', UTC_TIMESTAMP(), ?)")
                       ->execute([$kind === 'scheduled' ? 'scheduled' : 'manual', $by]);
        } catch (PDOException $e) {
            // Without its history table (Database Verification not run yet) a backup cannot be
            // recorded: it does not run, and administrators are told rather than left guessing.
            $out['error'] = $e->getCode() === '42S02'
                ? backupT('err_history_missing')
                : backupT('err_database');
            $this->notify($out['error']);
            return $out;
        }
        $runId = (int)$this->conn->lastInsertId();
        $out['run_id'] = $runId;
        $warnings = [];
        $set = null;
        $complete = false;
        $this->seen = [];
        $this->uploaded = [];
        try {
            if (!backupSodiumAvailable()) throw new RuntimeException(backupT('err_sodium'));
            $keyring   = backupKeyring($this->conn);
            $public    = base64_decode(backupSetting($this->conn, 'backup_public_key'), true);
            $installId = $this->installId($warnings);
            if ($keyring === null || !$public || $installId === '') throw new RuntimeException(backupT('err_no_passphrase'));
            // Seal only to the public key of the keyring the passphrase opens: a mismatch (settings changed
            // half way, or by hand) would make a backup nobody can open.
            if (!hash_equals((string)($keyring['public'] ?? ''), base64_encode($public))) throw new RuntimeException(backupT('err_keyring_mismatch'));
            $poolKey = backupPoolNameKey($this->conn);

            $this->tmp = sys_get_temp_dir() . '/freeitsm-backup-' . bin2hex(random_bytes(6));
            if (!@mkdir($this->tmp, 0700)) throw new RuntimeException(backupT('err_tmp'));

            $set = $this->newSetName();
            $out['set'] = $set;
            $this->putString("sets/$set/owner.json", json_encode(['install_id' => $installId, 'started_at' => gmdate('c')]));
            $this->conn->prepare('UPDATE backup_runs SET set_name = ? WHERE id = ?')->execute([$set, $runId]);

            // 1. The database and the list of Files keys, at one moment. Lists go to files, not memory:
            //    an install can hold hundreds of thousands of files (CLI memory_limit is often 128M).
            $dump = $this->tmp . '/db.dump';
            $inv = fopen($this->tmp . '/inventory.jsonl', 'w+b');
            $this->conn->exec('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            $this->conn->beginTransaction();
            try {
                $info = backupDumpDatabase($this->conn, $dump);
                $this->conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
                try {
                    $st = $this->conn->query('SELECT storage_path, MAX(sha256) AS sha256, MAX(size_bytes) AS size_bytes
                                                FROM files_versions GROUP BY storage_path ORDER BY storage_path');
                    foreach ($st as $k) {
                        fwrite($inv, json_encode(['store' => 'files', 'path' => (string)$k['storage_path'],
                            'known_sha' => preg_match('/^[0-9a-f]{64}$/', (string)$k['sha256']) ? (string)$k['sha256'] : null,
                            'known_size' => (int)$k['size_bytes']], JSON_UNESCAPED_SLASHES) . "\n");
                    }
                    $st->closeCursor();
                } finally {
                    $this->conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
                }
                $this->conn->commit();
            } catch (Throwable $e) {
                if ($this->conn->inTransaction()) $this->conn->rollBack();
                throw $e;
            }

            // 2. Every other stored file.
            foreach (self::uploadFolderFiles($this->appRoot, filesStorageRoot($this->conn)) as $f) fwrite($inv, json_encode($f, JSON_UNESCAPED_SLASHES) . "\n");
            if ($this->afterInventory) ($this->afterInventory)();

            // 3. Pool every file. The pool is listed once (checking each object would be a request
            //    per file, two on S3, every run), into a compact map (loadPool()).
            $this->loadPool();
            $dataKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
            $list = fopen($this->tmp . '/files.jsonl', 'w+b');   // the manifest's file entries, one per line
            $refs = [];                                           // binary pool name => plain size
            $plainTotal = 0;
            $count = 0;
            rewind($inv);
            while (($line = fgets($inv)) !== false) {
                $entry = $this->poolFile(json_decode($line, true), $poolKey, $public, $out, $warnings);
                fwrite($list, json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n");
                $count++;
                if (isset($entry['pool'])) {
                    $refs[hex2bin($entry['pool'])] = (int)$entry['size'];
                    $plainTotal += (int)$entry['size'];
                }
            }
            fclose($inv);
            @unlink($this->tmp . '/inventory.jsonl');

            // 4. The set itself.
            $this->putEncrypted("sets/$set/db.bin", $dump, $dataKey);
            $keyFile = $this->keyPath !== '' && is_file($this->keyPath) ? $this->keyPath : null;
            if ($keyFile === null || ($keyBytes = @file_get_contents($keyFile)) === false) {
                throw new RuntimeException(backupT('err_key_unreadable'));
            }
            $this->putEncryptedString("sets/$set/key.bin", $keyBytes, $dataKey);
            // The manifest: a header line, then one line per file (streamed, never held whole).
            $header = [
                'format'      => BACKUP_MANIFEST_FORMAT,
                'app_version' => freeitsmVersion(),
                'created_at'  => gmdate('c'),
                'set'         => $set,
                'install_id'  => $installId,
                'db_name'     => (string)$this->conn->query('SELECT DATABASE()')->fetchColumn(),
                'tables'      => $info['tables'],
                'db'          => ['size' => (int)filesize($dump), 'sha256' => hash_file('sha256', $dump)],
                'key'         => ['size' => strlen($keyBytes), 'sha256' => hash('sha256', $keyBytes)],
                'file_count'  => $count,
            ];
            $mf = fopen($this->tmp . '/manifest.jsonl', 'wb');
            fwrite($mf, json_encode($header, JSON_UNESCAPED_SLASHES) . "\n");
            rewind($list);
            stream_copy_to_stream($list, $mf);
            fclose($mf);
            fclose($list);
            @unlink($this->tmp . '/files.jsonl');
            backupEncryptFile($this->tmp . '/manifest.jsonl', $this->tmp . '/manifest.bin', $dataKey);
            @unlink($this->tmp . '/manifest.jsonl');
            $datakeyBin = backupSealKey($dataKey, $public);
            $this->target->putFile("sets/$set/manifest.bin", $this->tmp . '/manifest.bin');
            $this->putString("sets/$set/datakey.bin", $datakeyBin);
            $this->putString("sets/$set/auth.txt", backupSetAuth($poolKey, $set, $datakeyBin, hash_file('sha256', $this->tmp . '/manifest.bin')));
            @unlink($this->tmp . '/manifest.bin');
            ksort($refs, SORT_STRING);   // binary order is the order of the hex names
            $rf = fopen($this->tmp . '/refs.txt', 'wb');
            foreach ($refs as $b => $size) fwrite($rf, bin2hex($b) . "\n");
            fclose($rf);
            $this->target->putFile("sets/$set/refs.txt", $this->tmp . '/refs.txt');
            @unlink($this->tmp . '/refs.txt');
            $this->putString("sets/$set/keyring.json", json_encode($keyring, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            sodium_memzero($dataKey);

            // 5. Automatic verification: everything it refers to is there at the expected size
            //    (read back by listing, as the target now holds it - streamed, flags per referenced name).
            $written = $this->target->listObjects("sets/$set/");
            foreach (['db.bin', 'key.bin', 'manifest.bin', 'datakey.bin', 'auth.txt', 'refs.txt', 'keyring.json'] as $o) {
                if (!isset($written["sets/$set/$o"])) throw new RuntimeException(backupT('err_written_missing', ['object' => $o]));
            }
            $found = [];
            $this->target->eachObject('pool/', function (string $k, int $size) use (&$found, $refs) {
                $name = substr($k, 5);
                $isKey = str_ends_with($name, '.key');
                $hex = $isKey ? substr($name, 0, -4) : $name;
                if (strlen($hex) !== 64 || !ctype_xdigit($hex)) return;
                $b = hex2bin($hex);
                if (!isset($refs[$b])) return;
                if ($isKey ? $size === BACKUP_SEALED_KEY_SIZE : $size === backupEncryptedSize($refs[$b])) $found[$b] = ($found[$b] ?? 0) | ($isKey ? 1 : 2);
            });
            foreach ($refs as $b => $size) {
                if (($found[$b] ?? 0) !== 3) throw new RuntimeException(backupT('err_pool_missing'));
            }
            unset($found);
            $this->sampleReused($refs);
            $this->putString("sets/$set/done.json", json_encode([
                'format' => BACKUP_MANIFEST_FORMAT, 'created_at' => gmdate('c'), 'install_id' => $installId,
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
                if ($out['prune']['gc_skipped']) $warnings[] = backupT('warn_gc_skipped', ['reason' => $out['prune']['gc_reason']]);
            } catch (Throwable $e) {
                $warnings[] = backupT('warn_prune_failed', ['error' => $e->getMessage()]);
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
            $this->notify($out['error'], $runId);
        } finally {
            if ($this->tmp !== '') self::rmTree($this->tmp);
            $this->tmp = '';
        }
        return $out;
    }

    /**
     * Removes sets beyond the newest $keep complete ones of this install and this
     * install's incomplete sets older than $incompleteMaxAge (runs that died), then every
     * pool object that no remaining set references and that is older than $gcGraceSeconds.
     *
     * Another install's sets are never touched. The pool clean-up reads every remaining
     * set's refs.txt FROM THE TARGET (right after a restore, or with two installs on one
     * target), and the grace period protects objects a run - ours, a clone's or another
     * install's - has just uploaded or is about to reuse. Any doubt about a complete
     * set's references skips the clean-up.
     *
     * @return array{sets_removed: int, pool_removed: int, gc_skipped: bool, gc_reason: ?string}
     */
    public function prune(int $keep, string $installId): array
    {
        // A Verify reading a backup must not have it (or the files it holds) removed under it.
        // Held for the whole prune, and Verify takes the same lock: neither runs under the other.
        $v = $this->conn->prepare('SELECT GET_LOCK(?, 0)');
        $v->execute([backupVerifyLockName($this->conn)]);
        if ((int)$v->fetchColumn() !== 1) return ['sets_removed' => 0, 'pool_removed' => 0, 'gc_skipped' => true, 'gc_reason' => backupT('prune_verify_running')];
        try {
            return $this->pruneLocked($keep, $installId);
        } finally {
            $this->conn->prepare('SELECT RELEASE_LOCK(?)')->execute([backupVerifyLockName($this->conn)]);
        }
    }

    private function pruneLocked(int $keep, string $installId): array
    {
        $sets = [];
        foreach ($this->target->listObjects('sets/') as $k => $o) {
            $parts = explode('/', $k, 3);
            if (count($parts) === 3) $sets[$parts[1]][$parts[2]] = $o;
        }
        $mine = [];
        $removed = 0;
        $gcSkip = null;
        foreach ($sets as $name => $objs) {
            $complete = isset($objs['done.json']);
            $owner = $complete ? $this->readJson("sets/$name/done.json")
                   : (isset($objs['owner.json']) ? $this->readJson("sets/$name/owner.json") : null);
            if ((is_array($owner) ? (string)($owner['install_id'] ?? '') : '') !== $installId) continue;   // not ours
            if ($complete) {
                $mine[] = $name;
                continue;
            }
            $started = is_array($owner) && isset($owner['started_at']) ? strtotime((string)$owner['started_at']) : false;
            if ($started === false) $started = max(array_map(fn($o) => (int)$o['mtime'], $objs));
            if (time() - $started > $this->incompleteMaxAge) {
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
        $used = [];
        try {
            foreach ($sets as $name => $objs) {
                if (!isset($objs['refs.txt'])) {
                    // A complete set always has one: without it, what it uses is unknown.
                    if (isset($objs['done.json'])) throw new RuntimeException('missing refs.txt');
                    continue;
                }
                // Read line by line from a file, into a binary-keyed map: one entry per pooled file.
                $p = ($this->tmp !== '' ? $this->tmp : sys_get_temp_dir()) . '/refs-' . bin2hex(random_bytes(4));
                try {
                    $this->target->readTo("sets/$name/refs.txt", $p);
                    $fh = fopen($p, 'rb');
                    if ($fh === false) throw new RuntimeException('refs.txt could not be read');
                    while (($n = fgets($fh)) !== false) {
                        $n = trim($n);
                        if (strlen($n) === 64 && ctype_xdigit($n)) $used[hex2bin($n)] = true;
                    }
                    fclose($fh);
                } finally {
                    @unlink($p);
                }
            }
        } catch (Throwable $e) {
            $gcSkip = backupT('prune_refs_unreadable');
        }
        if ($gcSkip === null) {
            $cutoff = time() - $this->gcGraceSeconds;
            $drop = [];   // unreferenced and old enough: usually few; deleted after the listing
            $this->target->eachObject('pool/', function (string $k, int $size, int $mtime) use (&$drop, $used, $cutoff) {
                $hex = preg_replace('/\.key$/', '', substr($k, 5));
                if ($mtime > $cutoff || (strlen($hex) === 64 && ctype_xdigit($hex) && isset($used[hex2bin($hex)]))) return;
                $drop[] = $k;
            });
            unset($used);
            $this->target->eachObject('quarantine/', function (string $k, int $size, int $mtime) use (&$drop) {
                if ($mtime < time() - self::QUARANTINE_DAYS * 86400) $drop[] = $k;
            });
            foreach ($drop as $k) {
                $this->target->delete($k);
                if (str_starts_with($k, 'pool/') && !str_ends_with($k, '.key')) $poolRemoved++;
            }
        }
        return ['sets_removed' => $removed, 'pool_removed' => $poolRemoved, 'gc_skipped' => $gcSkip !== null, 'gc_reason' => $gcSkip];
    }

    // ── internals ──

    /**
     * Every file a backup covers in the upload folders of the install at $appRoot, one at a time
     * (a generator: never the whole list in memory): every store in FILE_STORES from where it lives
     * now and the persistence folders no store covers (backupUploadFolders()), without SKIP_DIRS, the
     * local Files root ($filesRoot), protection files and symbolic links.
     *
     * @return iterable<array{store: string, path: string, base: string}>  store is 'dir:<rel>' (the
     *         store's default folder, so the manifest reads the same wherever a store has moved);
     *         base is the folder the file is in now
     */
    public static function uploadFolderFiles(string $appRoot, string $filesRoot): iterable
    {
        $appRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
        $skip = array_map(fn($d) => backupDefaultPath($appRoot, $d), self::SKIP_DIRS);
        $skip[] = rtrim(str_replace('\\', '/', $filesRoot), '/');
        $folders = backupUploadFolders($appRoot);
        foreach ($folders as $d) {
            $rel  = $d['rel'];
            $base = $d['path'];
            if (!is_dir($base)) continue;
            // A folder inside this one that is walked on its own (a store inside uploads/) is not walked
            // twice - nor a store's default folder that the store has left (what is there is not its files).
            $own = $skip;
            $inside = array_column($folders, 'path');
            foreach (FILE_STORES as $s) $inside[] = $appRoot . '/' . $s['folder'];
            foreach ($inside as $p) if ($p !== $base && str_starts_with($p, $base . '/')) $own[] = $p;
            $it = new RecursiveIteratorIterator(
                new RecursiveCallbackFilterIterator(
                    new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                    function (SplFileInfo $f) use ($own) {
                        $p = rtrim(str_replace('\\', '/', $f->getPathname()), '/');
                        foreach ($own as $s) if ($p === $s || str_starts_with($p, $s . '/')) return false;
                        return !$f->isLink();
                    }),
                RecursiveIteratorIterator::LEAVES_ONLY);
            foreach ($it as $f) {
                if (!$f->isFile() || backupIsProtectionFile($f->getFilename())) continue;   // the install's own copies count
                $p = str_replace('\\', '/', $f->getPathname());
                yield ['store' => 'dir:' . $rel, 'path' => substr($p, strlen($base) + 1), 'base' => $base];
            }
        }
    }

    /** Puts one file in the pool (or finds it there) and returns its manifest entry. */
    private function poolFile(array $f, string $poolKey, string $public, array &$out, array &$warnings): array
    {
        $entry = ['store' => $f['store'], 'path' => $f['path']];
        // A Files object whose checksum Files recorded and that is already in the pool is
        // not downloaded again: every run would otherwise read the whole Files bucket.
        if ($f['store'] === 'files' && ($f['known_sha'] ?? null) !== null) {
            $name = backupPoolName($poolKey, $f['known_sha']);
            if (isset($this->seen[hex2bin($name)]) || $this->inPool($name, (int)$f['known_size'])) {
                $this->seen[hex2bin($name)] = true;
                $out['files_total']++;
                return $entry + ['size' => (int)$f['known_size'], 'sha256' => $f['known_sha'], 'pool' => $name];
            }
        }
        $copy = null;
        if ($f['store'] === 'files') {
            $copy = $this->tmp . '/file.bin';
            try {
                filesStoreFor($this->conn, $f['path'])->readTo($f['path'], $copy);
            } catch (StorageNotFound $e) {
                $st = $this->conn->prepare('SELECT 1 FROM files_versions WHERE storage_path = ? LIMIT 1');
                $st->execute([$f['path']]);
                if ($st->fetchColumn()) throw new RuntimeException(backupT('err_files_missing', ['path' => $f['path']]));
                $warnings[] = backupT('warn_files_deleted', ['path' => $f['path']]);
                return $entry + ['missing' => 'deleted during backup'];
            } catch (StorageUnavailable $e) {
                throw new RuntimeException(backupT('err_files_unreadable', ['error' => $e->getMessage()]));
            }
            $local = $copy;
        } else {
            $local = $f['base'] . '/' . $f['path'];
        }
        $sha = @hash_file('sha256', $local);
        $size = @filesize($local);
        if ($sha === false || $size === false) {
            clearstatcache(true, $local);
            if ($copy === null && !file_exists($local)) {
                $warnings[] = backupT('warn_file_deleted', ['path' => substr($f['store'], 4) . '/' . $f['path']]);
                return $entry + ['missing' => 'deleted during backup'];
            }
            throw new RuntimeException(backupT('err_file_unreadable', ['path' => substr($f['store'], 4) . '/' . $f['path']]));
        }
        $name = backupPoolName($poolKey, $sha);
        $out['files_total']++;
        if (!isset($this->seen[hex2bin($name)]) && !$this->inPool($name, (int)$size)) {
            if ($this->beforeEncrypt) ($this->beforeEncrypt)($local);
            $fileKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
            $enc = $this->tmp . '/enc.bin';
            try {
                backupEncryptFile($local, $enc, $fileKey, $encSha, $encSize);
                if ($encSha !== $sha) {
                    // Changed since its checksum was taken: what was encrypted is what the backup holds.
                    $sha  = $encSha;
                    $size = $encSize;
                    $name = backupPoolName($poolKey, $sha);
                }
                if (!isset($this->seen[hex2bin($name)]) && !$this->inPool($name, (int)$size)) {
                    $this->target->putFile("pool/$name", $enc);
                    $this->putString("pool/$name.key", backupSealKey($fileKey, $public));
                    $this->notePool($name, backupEncryptedSize((int)$size));
                    $this->uploaded[hex2bin($name)] = true;
                    $this->notePool("$name.key", BACKUP_SEALED_KEY_SIZE);
                    $out['files_new']++;
                }
            } finally {
                sodium_memzero($fileKey);
                @unlink($enc);
            }
        }
        $this->seen[hex2bin($name)] = true;
        if ($copy !== null) @unlink($copy);
        return $entry + ['size' => (int)$size, 'sha256' => $sha, 'pool' => $name];
    }

    /** The object and its sealed key are on the target (as last listed), both at their exact sizes. */
    private function inPool(string $name, int $plainSize): bool
    {
        $v = $this->pool[hex2bin($name)] ?? 0;
        return ($v & 1) === 1 && ($v >> 1) - 1 === backupEncryptedSize($plainSize);
    }

    /**
     * This install's id. A database copied to another server or renamed (a clone, a test
     * copy) is another install: it gets its own id, so its pruning never counts - or
     * removes - the original's backups. Not knowable on servers without @@server_uuid.
     */
    private function installId(array &$warnings): string
    {
        $id = backupSetting($this->conn, 'backup_install_id');
        $fp = backupDatabaseFingerprint($this->conn);
        if ($id === '' || $fp === null) return $id;
        $saved = backupSetting($this->conn, 'backup_install_fingerprint');
        if ($saved !== '' && !hash_equals($saved, $fp)) {
            $id = bin2hex(random_bytes(16));
            backupSaveSetting($this->conn, 'backup_install_id', $id);
            $warnings[] = backupT('warn_moved');
        }
        if ($saved !== $fp) backupSaveSetting($this->conn, 'backup_install_fingerprint', $fp);
        return $id;
    }

    /** @var array<string,bool> pool names handled in this run (binary, 32 bytes) */
    private array $seen = [];

    /** @var array<string,bool> pool names uploaded by this run (binary) */
    private array $uploaded = [];

    /**
     * Reads back a random sample of the pooled files this set reuses (not uploaded by this run): each
     * must be a backup object (its header) of the exact length. One that is not is removed - the next
     * run uploads it again - and this run fails, saying so.
     *
     * @param array<string,int> $refs  binary pool name => plain size
     */
    private function sampleReused(array $refs): void
    {
        if ($this->sampleSize < 1 || !$refs) return;
        $picked = (array)array_rand($refs, min($this->sampleSize, count($refs)));
        foreach ($picked as $b) {
            if (isset($this->uploaded[$b])) continue;
            $hex = bin2hex($b);
            // Its length, and its first bytes by a ranged read - not a whole download.
            $head = '';
            try {
                $ok = $this->target->size("pool/$hex") === backupEncryptedSize($refs[$b]);
                if ($ok) {
                    $this->target->readRange("pool/$hex", 0, strlen(BACKUP_MAGIC) - 1, function (string $c) use (&$head) { $head .= $c; return true; });
                    $ok = $head === BACKUP_MAGIC;
                }
            } catch (StorageNotFound $e) {
                $ok = false;
            }
            if (!$ok) {
                $this->quarantine("pool/$hex");
                throw new RuntimeException(backupT('err_pool_damaged'));
            }
        }
    }

    /**
     * Moves a damaged pool object aside (quarantine/<name>.<time>) rather than deleting it: other sets,
     * or another install sharing the target, may refer to it, and someone may want to look at it. The
     * next run finds the name missing and stores the file again; prune() removes quarantined objects
     * after QUARANTINE_DAYS.
     */
    private function quarantine(string $key): void
    {
        $p = $this->tmp . '/quarantine.bin';
        try {
            $this->target->readTo($key, $p);
            $this->target->putFile('quarantine/' . substr($key, 5) . '.' . time(), $p);
            $this->target->delete($key);
        } catch (Throwable $e) {
            // the next run tries again
        } finally {
            @unlink($p);
        }
    }

    /**
     * The pool as last listed plus this run's uploads, compact (one entry per object, about 100 bytes):
     * binary pool name => bit 0 its sealed key is there at the right size, bits 1+ its size + 1.
     *
     * @var array<string,int>
     */
    private array $pool = [];

    /** Lists the pool once, streamed, into $this->pool. */
    private function loadPool(): void
    {
        $this->pool = [];
        $this->target->eachObject('pool/', fn(string $k, int $size) => $this->notePool(substr($k, 5), $size));
    }

    /** Records one pool object ('<hex>' or '<hex>.key') of $size bytes. Anything else in pool/ is ignored. */
    private function notePool(string $name, int $size): void
    {
        $isKey = str_ends_with($name, '.key');
        $hex = $isKey ? substr($name, 0, -4) : $name;
        if (strlen($hex) !== 64 || !ctype_xdigit($hex)) return;
        $b = hex2bin($hex);
        $v = $this->pool[$b] ?? 0;
        $this->pool[$b] = $isKey ? ($size === BACKUP_SEALED_KEY_SIZE ? $v | 1 : $v & ~1) : (($v & 1) | (($size + 1) << 1));
    }

    private function newSetName(): string
    {
        for ($i = 0; $i < 5; $i++) {
            $name = gmdate('Ymd\THis\Z');
            if (!$this->target->listKeys("sets/$name/")) return $name;
            sleep(1);
        }
        throw new RuntimeException(backupT('err_set_name'));
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
            if (file_put_contents($p, $plain) === false) throw new RuntimeException(backupT('err_tmp'));
            $this->putEncrypted($key, $p, $encKey);
        } finally {
            @unlink($p);
        }
    }

    private function putString(string $key, string $data): void
    {
        $p = ($this->tmp !== '' ? $this->tmp : sys_get_temp_dir()) . '/put-' . bin2hex(random_bytes(4));
        try {
            if (file_put_contents($p, $data) === false) throw new RuntimeException(backupT('err_tmp'));
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

    /** A failed backup: a bell and an email to the people concerned (includes/backup/notify.php). */
    private function notify(string $error, int $runId = 0): void
    {
        try {
            if ($this->mailer) {
                ($this->mailer)('FreeITSM backup failed', $error);
                return;
            }
            // Nobody's own action (a scheduled run; whoever pressed Back up now has long moved on).
            backupNotify($this->conn, 'failed', backupT('n_failed_title'), backupT('n_failed', ['error' => $error]), null, max(1, $runId));
        } catch (Throwable $e) {
            // the run is still recorded as failed on the page and in Background jobs
        }
    }

    /** Our own message; never a database or library dump. */
    private static function cleanError(Throwable $e): string
    {
        if ($e instanceof PDOException) return backupT('err_database');
        return mb_substr(trim($e->getMessage()), 0, 1000) ?: backupT('err_failed');
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

/**
 * A store's folder for the install at $appRoot: where it lives now (fileStoreDir()) for this
 * install, its default folder under $appRoot for any other (a scratch restore, --app-root).
 *
 * @param string $store  a FILE_STORES key
 */
function backupStoreDir(string $appRoot, string $store): string
{
    $root = rtrim(str_replace('\\', '/', $appRoot), '/');
    $own  = rtrim(str_replace('\\', '/', fileStoreAppRoot()), '/');
    $same = $root === $own || ((realpath($root) ?: '') !== '' && realpath($root) === realpath($own));
    return $same ? rtrim(str_replace('\\', '/', fileStoreDir($store)), '/') : $root . '/' . FILE_STORES[$store]['folder'];
}

/**
 * Where a path in the default layout (relative to the app, e.g. 'uploads/documents/a/b.pdf')
 * is now: inside the store whose default folder holds it, wherever that store lives; anything
 * else stays under $appRoot.
 */
function backupDefaultPath(string $appRoot, string $rel): string
{
    $best = null;
    foreach (FILE_STORES as $id => $s) {
        $f = $s['folder'];
        if (($rel === $f || str_starts_with($rel, $f . '/')) && ($best === null || strlen($f) > strlen(FILE_STORES[$best]['folder']))) $best = $id;
    }
    if ($best === null) return rtrim(str_replace('\\', '/', $appRoot), '/') . '/' . $rel;
    $rest = substr($rel, strlen(FILE_STORES[$best]['folder']));
    return backupStoreDir($appRoot, $best) . $rest;
}

/**
 * The folders a backup walks: every store in FILE_STORES (includes/file_stores.php) from
 * where it lives now, named after its DEFAULT folder - so a backup reads the same, and still
 * restores, wherever a store is moved later - and every other persistence folder that no
 * store covers (uploads/ itself, for what is not a store). The encryption key is backed up on
 * its own; Files content is read from Files storage.
 *
 * @return array<int, array{rel: string, path: string}>  rel = the manifest's 'dir:<rel>'
 */
function backupUploadFolders(string $appRoot): array
{
    $out = [];
    $defaults = [];
    foreach (FILE_STORES as $id => $s) {
        $out[] = ['rel' => $s['folder'], 'path' => backupStoreDir($appRoot, $id)];
        $defaults[$s['folder']] = true;
    }
    foreach (storagePersistenceDirectories() as $d) {
        if (!empty($d['critical']) || isset($defaults[(string)$d['rel']])) continue;
        $out[] = ['rel' => (string)$d['rel'], 'path' => backupDefaultPath($appRoot, (string)$d['rel'])];
    }
    return $out;
}

/**
 * The files the app ships in the upload folders to protect them (.htaccess, web.config - the only
 * ones it ships there): never backed up, never written by a restore, never removed by a rollback.
 * The install's own copies are the ones that count. Any other file, a dot file uploaded by someone
 * included, is data and is backed up.
 */
function backupIsProtectionFile(string $path): bool
{
    $name = basename(str_replace('\\', '/', $path));
    return strcasecmp($name, '.htaccess') === 0 || strcasecmp($name, 'web.config') === 0;
}

