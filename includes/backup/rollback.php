<?php
/**
 * In-app rollback (System -> Backups -> Restore): puts the whole install back to one
 * backup - database, upload folders and Files content - as a true rollback.
 *
 * Runs in the background job cron/backup_rollback.php, under maintenance mode (switched on
 * by BackupsService::restoreStart() before the job starts, so the browser holds its token):
 *
 *   1. open the backup with the passphrase (nothing changes if that fails);
 *   2. wait for running background jobs, then hold the backup job's lock;
 *   3. take a safety backup of the current state (kind "safety": never prunes);
 *   4. note this install's own backup and Files storage settings, the backup schedule and
 *      the backup history - they describe this install now, not the install in the backup;
 *   5. restore the backup into the current stores and delete what it does not list;
 *   6. run Database Verification (an older backup's schema is brought up to date);
 *   7. put back what step 4 noted (re-encrypted if the backup's key differs), record the
 *      restore in the history, and switch maintenance mode off.
 *
 * If anything fails once step 5 has begun, the safety backup is restored the same way.
 * If that fails too, maintenance mode stays on ("broken") and the page says what to do.
 */

require_once __DIR__ . '/restore.php';
require_once __DIR__ . '/maintenance.php';
require_once __DIR__ . '/../job_runs.php';
require_once __DIR__ . '/../job_registry.php';

/** Settings that describe this install, not the backup: put back after a rollback (with BACKUP_SETTING_KEYS). */
const BACKUP_ROLLBACK_KEEP_SETTINGS = [
    'files_storage_driver', 'files_storage_root', 'files_storage_previous',
    'files_s3_endpoint', 'files_s3_region', 'files_s3_bucket', 'files_s3_access_key_id',
    'files_s3_secret', 'files_s3_prefix', 'files_s3_path_style',
];

final class BackupRollback
{
    /** How long to wait for running background jobs before giving up. */
    public int $jobWaitSeconds = 600;

    /** fn(): bool - Database Verification; true when it succeeded. */
    public Closure $verifySchema;

    /** Test hook: runs after the database is restored (throw to simulate a failure). */
    public ?Closure $failAfterDatabase = null;

    private PDO $conn;
    private StorageDriver&StorageLister $target;
    private string $set;
    private string $passphrase;
    private int $by;
    private string $appRoot;
    private string $keyPath;
    private StorageDriver $files;
    private ?Closure $mailer;
    private int $lastBeat = 0;
    private array $warnings = [];
    private ?array $snapshot = null;

    /**
     * @param StorageDriver $files   the Files store as it is NOW (files are restored into it)
     * @param callable|null $mailer  fn(string $subject, string $body): void - told when it fails
     *                               (default: every active administrator, by email)
     */
    public function __construct(PDO $conn, StorageDriver&StorageLister $target, string $set, string $passphrase, int $by,
                                string $appRoot, string $keyPath, StorageDriver $files, ?callable $mailer = null)
    {
        $this->conn = $conn;
        $this->target = $target;
        $this->set = $set;
        $this->passphrase = $passphrase;
        $this->by = $by;
        $this->appRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
        $this->keyPath = $keyPath;
        $this->files = $files;
        $this->mailer = $mailer !== null ? Closure::fromCallable($mailer) : null;
        $this->verifySchema = function (): bool {
            $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__, 2) . '/scripts/db_verify_cli.php') . ' --apply --quiet';
            exec($cmd . ' 2>&1', $out, $code);
            return $code === 0;
        };
    }

    /**
     * Runs the rollback. Never throws: the outcome is in maintenance mode's file and returned.
     *
     * @return array{state: string, error: ?string, safety_set: ?string, warnings: string[]}
     *   state: done | failed (the install is as it was) | broken (maintenance mode stays on)
     */
    public function run(): array
    {
        $started = gmdate('Y-m-d H:i:s');
        $safety = null;
        $touched = false;
        $locked = false;
        try {
            if ((int)$this->conn->query('SELECT @@SESSION.wait_timeout')->fetchColumn() < 86400) $this->conn->exec('SET SESSION wait_timeout = 86400');
            if (backupSetting($this->conn, 'files_storage_previous') !== '') {
                throw new RuntimeException('Files is moving to another storage location. Restore when the move has finished.');
            }
            $this->beat(['state' => 'starting'], "Opening backup {$this->set}...");
            $open = backupOpenSet($this->target, $this->set, $this->passphrase);
            sodium_memzero($open['keys']['secret']);
            $m = $open['manifest'];
            $this->beat([], 'Backup ' . $this->set . ': FreeITSM ' . ($m['app_version'] ?? '?') . ', files ' . count((array)$m['files']) . '.');

            $this->beat(['state' => 'waiting'], 'Waiting for background jobs to finish...');
            $locked = $this->waitForJobs();

            $this->beat(['state' => 'safety'], 'Taking a safety backup of the current state...');
            $runner = new BackupRunner($this->conn, $this->target, $this->appRoot, $this->mailer, $this->keyPath);
            $runner->onFile = fn() => $this->beat();
            $r = $runner->run('safety', $this->by);
            if ($r['status'] !== 'ok') throw new RuntimeException('The safety backup failed, so nothing was restored: ' . $r['error']);
            $safety = (string)$r['set'];
            $this->beat(['safety_set' => $safety], "Safety backup $safety taken.");

            $this->snapshot = $this->takeSnapshot();
            $filesRoot = filesStorageRoot($this->conn);
            $touched = true;
            $this->restore($this->set, $filesRoot, true);
            $this->finish('done', null, $started, $safety);
            return $this->outcome('done', null, $safety);
        } catch (Throwable $e) {
            $error = $e instanceof BackupWrongPassphrase ? 'The passphrase does not open this backup.' : $e->getMessage();
            if (!$touched) {
                $this->beat([], 'Stopped: ' . $error);
                $this->finish('failed', $error, $started, $safety);
                return $this->outcome('failed', $error, $safety);
            }
            // The database or the files have been touched: put the safety backup back.
            $this->beat(['state' => 'recovering', 'error' => $error], "Failed: $error");
            $this->beat([], "Putting back safety backup $safety...");
            try {
                $this->restore((string)$safety, (string)$filesRoot, false);
                $this->finish('failed', $error, $started, $safety);
                $this->notify("The restore of backup {$this->set} failed, and FreeITSM was put back as it was before it (safety backup $safety). The error: $error");
                return $this->outcome('failed', $error, $safety);
            } catch (Throwable $e2) {
                $broken = $error . ' Putting back the safety backup also failed: ' . $e2->getMessage();
                $this->beat(['state' => 'broken', 'error' => $broken], 'Putting back the safety backup failed: ' . $e2->getMessage());
                $this->notify("The restore of backup {$this->set} failed part way, and putting back safety backup $safety failed too. FreeITSM is in maintenance mode. "
                            . "On the server: php scripts/backup_restore.php --set=$safety --force (it asks for the target and the passphrase), "
                            . "then php scripts/backup_maintenance.php --off. A command-line restore pauses scheduled backups and gives the install a new backup id: "
                            . "turn backups back on in System -> Backups, and remove older backups from the target yourself when no longer needed. $broken");
                return $this->outcome('broken', $broken, $safety);
            }
        } finally {
            if ($locked) JobRun::unlock($this->conn, 'backup');
        }
    }

    /** Restores one set into the current stores, deletes what it does not list, checks the schema and re-applies this install's settings. */
    private function restore(string $set, string $filesRoot, bool $isTarget): void
    {
        $this->beat(['state' => 'restoring'], "Restoring backup $set...");
        $r = new BackupRestore($this->target, $set, $this->passphrase, $this->conn, $this->appRoot, $this->keyPath, true,
                               fn(string $line) => $this->beat([], $line), $this->files);
        $r->removeExtrasFilesRoot = $filesRoot;
        $r->onFile = fn() => $this->beat();
        $r->afterDatabaseHook = function (PDO $db, string $keyHex) use ($isTarget) {
            $this->snapshot['key_hex'] = $keyHex;
            $this->beat(['state' => 'files'], 'Restoring the files...');
            if ($isTarget && $this->failAfterDatabase) ($this->failAfterDatabase)();
        };
        $res = $r->run();
        foreach ($res['warnings'] as $w) $this->warnings[] = $w;
        if (!$res['ok']) {
            throw new RuntimeException(count($res['errors']) . ' file(s) could not be restored, for example ' . $res['errors'][0]);
        }
        $this->beat(['state' => 'verifying'], 'Running Database Verification...');
        if (!($this->verifySchema)()) $this->warnings[] = 'Database Verification reported a problem: run it from System -> Database.';
        $this->applySnapshot();
    }

    /** What describes this install now: its backup and Files storage settings, the backup schedule and history. */
    private function takeSnapshot(): array
    {
        $keys = array_merge(BACKUP_SETTING_KEYS, BACKUP_ROLLBACK_KEEP_SETTINGS);
        $s = $this->conn->prepare('SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN (' . implode(',', array_fill(0, count($keys), '?')) . ')');
        $s->execute($keys);
        $currentKey = is_file($this->keyPath) ? trim((string)file_get_contents($this->keyPath)) : '';
        $settings = [];
        foreach ($s->fetchAll(PDO::FETCH_KEY_PAIR) as $k => $v) {
            $v = (string)$v;
            $plain = str_starts_with($v, 'ENC:') ? backupDecryptWithKey($v, $currentKey) : null;
            $settings[$k] = ['raw' => $v, 'plain' => $plain !== '' ? $plain : null];
        }
        $schedule = $this->conn->query("SELECT * FROM job_schedules WHERE job_key = 'backup'")->fetch(PDO::FETCH_ASSOC) ?: null;
        $runs = $this->conn->query('SELECT * FROM backup_runs ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        return ['keys' => $keys, 'settings' => $settings, 'schedule' => $schedule, 'runs' => $runs, 'current_key' => $currentKey, 'key_hex' => $currentKey];
    }

    /** Puts back what takeSnapshot() noted, after the database has been replaced. */
    private function applySnapshot(): void
    {
        $snap = $this->snapshot;
        $sameKey = hash_equals((string)$snap['current_key'], (string)$snap['key_hex']);
        $keys = $snap['keys'];
        $this->conn->prepare('DELETE FROM system_settings WHERE setting_key IN (' . implode(',', array_fill(0, count($keys), '?')) . ')')->execute($keys);
        $ins = $this->conn->prepare('INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)');
        foreach ($snap['settings'] as $k => $v) {
            // An encrypted value is re-encrypted when the restored key is not the one it was written with.
            $value = $sameKey || $v['plain'] === null ? $v['raw'] : backupEncryptWithKey($v['plain'], (string)$snap['key_hex']);
            $ins->execute([$k, $value]);
        }
        try {
            $this->conn->exec("DELETE FROM job_schedules WHERE job_key = 'backup'");
            if ($snap['schedule'] !== null) $this->insertRow('job_schedules', $snap['schedule']);
        } catch (PDOException $e) {
            $this->warnings[] = 'The backup schedule could not be put back: check it on System -> Backups.';
        }
        try {
            $this->conn->exec('DELETE FROM backup_runs');
            foreach ($snap['runs'] as $row) $this->insertRow('backup_runs', $row);
        } catch (PDOException $e) {
            $this->warnings[] = 'The backup history could not be put back.';
        }
        FilesStorageCache::$settings = [];   // read again from the restored database (the drivers are this install's, unchanged)
    }

    private function insertRow(string $table, array $row): void
    {
        $cols = array_keys($row);
        $this->conn->prepare('INSERT INTO ' . backupIdent($table) . ' (' . implode(', ', array_map('backupIdent', $cols)) . ') VALUES ('
                           . implode(', ', array_fill(0, count($cols), '?')) . ')')->execute(array_values($row));
    }

    /** Waits for every running background job, then holds the backup job's lock. @throws RuntimeException */
    private function waitForJobs(): bool
    {
        $until = time() + $this->jobWaitSeconds;
        while (true) {
            $busy = [];
            foreach (array_keys(jobRegistry()) as $job) {
                if ($job === 'backup') continue;
                $s = $this->conn->prepare('SELECT IS_USED_LOCK(?) IS NOT NULL');
                $s->execute([JobRun::lockName($this->conn, $job)]);
                if ((int)$s->fetchColumn() === 1) $busy[] = $job;
            }
            if (!$busy && JobRun::tryLock($this->conn, 'backup')) return true;
            if (!$busy) $busy[] = 'backup';
            if (time() >= $until) {
                throw new RuntimeException('These background jobs are still running: ' . implode(', ', $busy) . '. Nothing was changed; try again when they have finished.');
            }
            $this->beat([], 'Still running: ' . implode(', ', $busy));
            sleep(min(3, max(1, $until - time())));
        }
    }

    /** Records the outcome in the history and switches maintenance mode off. */
    private function finish(string $state, ?string $error, string $started, ?string $safety): void
    {
        try {
            $this->conn->prepare("INSERT INTO backup_runs (kind, status, set_name, started_at, finished_at, started_by, error_text, warning_text)
                                  VALUES ('restore', ?, ?, ?, UTC_TIMESTAMP(), ?, ?, ?)")
                       ->execute([$state === 'done' ? 'ok' : 'failed', $this->set, $started, $this->by, $error,
                                  $this->warnings ? implode("\n", array_slice($this->warnings, 0, 50)) : null]);
        } catch (Throwable $e) {
            $this->warnings[] = 'The restore could not be recorded in the backup history.';
        }
        $this->beat([], $state === 'done' ? "Backup {$this->set} restored." : 'Not restored: ' . $error);
        backupMaintenanceEnd(['state' => $state, 'error' => $error, 'safety_set' => $safety, 'warnings' => $this->warnings]);
    }

    private function outcome(string $state, ?string $error, ?string $safety): array
    {
        return ['state' => $state, 'error' => $error, 'safety_set' => $safety, 'warnings' => $this->warnings];
    }

    /** Progress into maintenance mode's file: every line, and the heartbeat at most every few seconds. */
    private function beat(array $changes = [], ?string $line = null): void
    {
        if (!$changes && $line === null && time() - $this->lastBeat < 5) return;
        $this->lastBeat = time();
        try {
            backupMaintenanceUpdate($changes, $line);
        } catch (Throwable $e) {
            // the rollback carries on; the page shows the last state it could read
        }
    }

    private function notify(string $message): void
    {
        try {
            if ($this->mailer) {
                ($this->mailer)('FreeITSM restore failed', $message);
                return;
            }
            backupMailAdmins($this->conn, 'FreeITSM restore failed', '<p>' . htmlspecialchars($message) . '</p>');
        } catch (Throwable $e) {
            // the outcome is on the page and in the history
        }
    }
}

/** A value encrypted as encryptValue() does, with a given key (the restored one, not this process's cached key). */
function backupEncryptWithKey(string $plain, string $keyHex): string
{
    $key = @hex2bin($keyHex);
    if ($key === false || strlen($key) !== 32) throw new RuntimeException('The restored encryption key is not valid.');
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new RuntimeException('A setting could not be encrypted with the restored key.');
    return 'ENC:' . base64_encode($iv . $tag . $ct);
}
