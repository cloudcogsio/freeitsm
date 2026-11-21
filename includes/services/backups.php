<?php
/**
 * Backups (#286) - the one write path for System -> Backups: the target, the
 * passphrase keyring, the schedule, starting a backup and verifying one.
 * Used by api/system/backups.php; the job is cron/backup.php (includes/backup/runner.php).
 *
 * Input errors throw BackupsInputError whose message is a key under
 * system.backups (err_*), for the page to translate.
 */

require_once __DIR__ . '/../backup/crypto.php';
require_once __DIR__ . '/../backup/target.php';
require_once __DIR__ . '/../job_runs.php';
require_once __DIR__ . '/../job_registry.php';
require_once __DIR__ . '/../job_scheduler.php';
require_once __DIR__ . '/files_storage.php';

class BackupsInputError extends InvalidArgumentException {}

final class BackupsService
{
    public const PASSPHRASE_MIN = 12;
    public const KEEP_DEFAULT = 7;
    public const KEEP_MAX = 365;
    /** A Verify still "running" after this long was killed (by a web server timeout): shown as interrupted. */
    public const VERIFY_STALE_SECONDS = 7200;

    /** Key derivation cost; tests lower it. Null = libsodium's MODERATE. */
    public static ?int $kdfOps = null;
    public static ?int $kdfMem = null;

    /** Everything the page shows. Never contains a secret. */
    public static function describe(PDO $conn): array
    {
        $cfg = backupTargetConfig($conn);
        $target = null;
        if ($cfg !== null && $cfg['type'] === 'folder') {
            $target = ['type' => 'folder', 'folder' => $cfg['folder']];
        } elseif ($cfg !== null) {
            $s3 = $cfg;
            unset($s3['type']);
            $s3['secret'] = $s3['secret'] !== '' ? maskSecret($s3['secret']) : '';
            $target = ['type' => 's3', 's3' => $s3];
        }
        $weekday = (int)backupSetting($conn, 'backup_weekday', '0');
        return [
            'target'         => $target,
            'has_passphrase' => backupKeyring($conn) !== null,
            'schedule'       => [
                'mode'    => self::scheduleMode($conn),
                'weekday' => $weekday >= 1 && $weekday <= 7 ? $weekday : null,
                'time'    => backupSetting($conn, 'backup_time') ?: null,
            ],
            'keep'           => self::keepCount($conn),
            'sodium'         => backupSodiumAvailable(),
            'curl'           => extension_loaded('curl'),
            'running'        => self::isRunning($conn),
            'last_restore'   => self::lastRestore(),
            'restore_confirm' => self::RESTORE_CONFIRM,
        ];
    }

    public static function scheduleMode(PDO $conn): string
    {
        $m = backupSetting($conn, 'backup_schedule', 'off');
        return in_array($m, ['daily', 'weekly'], true) ? $m : 'off';
    }

    public static function keepCount(PDO $conn): int
    {
        $k = (int)backupSetting($conn, 'backup_keep_count', (string)self::KEEP_DEFAULT);
        return $k >= 1 && $k <= self::KEEP_MAX ? $k : self::KEEP_DEFAULT;
    }

    /** True while a backup holds the job's lock. */
    public static function isRunning(PDO $conn): bool
    {
        $s = $conn->prepare('SELECT IS_USED_LOCK(?) IS NOT NULL');
        $s->execute([JobRun::lockName($conn, 'backup')]);
        return (int)$s->fetchColumn() === 1;
    }

    /**
     * Writes, reads back, lists and deletes a small object on the target.
     *
     * @param array $in  ['type' => 'folder', 'folder' => ...] or ['type' => 's3', 's3' => [...]]
     *                   (a masked secret means the saved one, which needs $conn)
     * @return array ['ok' => bool, 'step' => 'connect'|'write'|'read'|'list'|'delete'|null, 'error' => ?string]
     */
    public static function test(array $in, ?PDO $conn = null): array
    {
        $step = 'connect';
        $tmp  = tempnam(sys_get_temp_dir(), 'bkt');
        $key  = '_freeitsm_test/' . bin2hex(random_bytes(16)) . '.txt';
        try {
            $cfg = self::targetFromInput($in, $conn);
            if ($cfg['type'] === 'folder' && !is_dir($cfg['folder'])) throw new RuntimeException('That folder does not exist on the server.');
            if ($cfg['type'] === 's3') {
                $refusal = FilesStorageService::endpointRefusal($cfg['endpoint']);
                if ($refusal !== null) throw new RuntimeException($refusal);
            }
            $d = backupTargetDriver($cfg);
            $bytes = random_bytes(32);
            file_put_contents($tmp, $bytes);
            $step = 'write';
            $d->putFile($key, $tmp);
            $step = 'read';
            $d->readTo($key, $tmp);
            if (file_get_contents($tmp) !== $bytes) throw new RuntimeException('The file read back was not the file written.');
            $step = 'list';
            if (!in_array($key, $d->listKeys('_freeitsm_test/'), true)) throw new RuntimeException('The file written was not in the listing.');
            $step = 'delete';
            $d->delete($key);
            return ['ok' => true, 'step' => null, 'error' => null];
        } catch (BackupsInputError $e) {
            return ['ok' => false, 'step' => 'connect', 'error' => $e->getMessage()];
        } catch (Throwable $e) {
            if ($step === 'write' && str_starts_with($e->getMessage(), 'Storage could not be reached')) $step = 'connect';
            return ['ok' => false, 'step' => $step, 'error' => $e->getMessage()];
        } finally {
            @unlink($tmp);
        }
    }

    /** Saves the target after it passes test(). An existing keyring is written there too. */
    public static function saveTarget(PDO $conn, array $in, int $by): void
    {
        $cfg = self::targetFromInput($in, $conn);
        if (self::isRunning($conn)) throw new BackupsInputError('err_running');
        if (!self::test($in, $conn)['ok']) throw new BackupsInputError('err_target_test');
        $keyring = backupKeyring($conn);
        if ($keyring !== null) backupWriteKeyring(backupTargetDriver($cfg), $keyring);

        backupSaveSetting($conn, 'backup_target', $cfg['type']);
        if ($cfg['type'] === 'folder') {
            backupSaveSetting($conn, 'backup_folder', $cfg['folder']);
            foreach (['endpoint', 'region', 'bucket', 'access_key_id', 'secret', 'prefix', 'path_style'] as $k) {
                backupSaveSetting($conn, 'backup_s3_' . $k, null);
            }
        } else {
            backupSaveSetting($conn, 'backup_folder', null);
            foreach (['endpoint', 'region', 'bucket', 'access_key_id', 'prefix'] as $k) {
                backupSaveSetting($conn, 'backup_s3_' . $k, (string)$cfg[$k]);
            }
            backupSaveSetting($conn, 'backup_s3_secret', encryptValue($cfg['secret']));
            backupSaveSetting($conn, 'backup_s3_path_style', $cfg['path_style'] ? '1' : '0');
        }
    }

    /** First-time passphrase: creates the keypair, the pool name key and this install's id. */
    public static function setPassphrase(PDO $conn, string $pass, string $confirm, int $by): void
    {
        if (backupKeyring($conn) !== null) throw new BackupsInputError('err_passphrase_exists');
        self::checkNewPassphrase($pass, $confirm);
        if (!backupSodiumAvailable()) throw new BackupsInputError('err_sodium');
        $kr = backupNewKeyring($pass, self::$kdfOps, self::$kdfMem);
        $cfg = backupTargetConfig($conn);
        if ($cfg !== null) {
            try {
                backupWriteKeyring(backupTargetDriver($cfg), $kr['keyring']);
            } catch (Throwable $e) {
                throw new BackupsInputError('err_target_unreachable');
            }
        }
        backupSaveSetting($conn, 'backup_public_key', $kr['public']);
        backupSaveSetting($conn, 'backup_keyring', json_encode($kr['keyring']));
        backupSaveSetting($conn, 'backup_pool_name_secret', encryptValue(bin2hex($kr['pool_name_key'])));
        if (backupSetting($conn, 'backup_install_id') === '') {
            backupSaveSetting($conn, 'backup_install_id', bin2hex(random_bytes(16)));
        }
    }

    /** New passphrase for the same keys: every existing backup opens with it. */
    public static function changePassphrase(PDO $conn, string $old, string $new, string $confirm, int $by): void
    {
        $kr = backupKeyring($conn);
        if ($kr === null) throw new BackupsInputError('err_no_passphrase');
        self::checkNewPassphrase($new, $confirm);
        try {
            $re = backupRekeyKeyring($kr, $old, $new);
        } catch (BackupWrongPassphrase $e) {
            throw new BackupsInputError('err_passphrase_wrong');
        }
        $cfg = backupTargetConfig($conn);
        if ($cfg !== null) {
            try {
                backupWriteKeyring(backupTargetDriver($cfg), $re);
            } catch (Throwable $e) {
                throw new BackupsInputError('err_target_unreachable');
            }
        }
        backupSaveSetting($conn, 'backup_keyring', json_encode($re));
    }

    /**
     * @param string      $mode     off | daily | weekly
     * @param int|null    $weekday  1 (Monday) .. 7 (Sunday), weekly only
     * @param string|null $time     HH:MM in the install's time zone (daily, weekly)
     */
    public static function saveSchedule(PDO $conn, string $mode, ?int $weekday, ?string $time, int $keep, int $by): void
    {
        if (!in_array($mode, ['off', 'daily', 'weekly'], true)) throw new BackupsInputError('err_schedule_mode');
        if ($keep < 1 || $keep > self::KEEP_MAX) throw new BackupsInputError('err_keep');
        if ($mode !== 'off' && ($time === null || !preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $time))) {
            throw new BackupsInputError('err_schedule_time');
        }
        if ($mode === 'weekly' && ($weekday === null || $weekday < 1 || $weekday > 7)) throw new BackupsInputError('err_schedule_day');

        backupSaveSetting($conn, 'backup_schedule', $mode);
        backupSaveSetting($conn, 'backup_weekday', $mode === 'weekly' ? (string)$weekday : null);
        backupSaveSetting($conn, 'backup_time', $mode === 'off' ? null : $time);
        backupSaveSetting($conn, 'backup_keep_count', (string)$keep);
        // Weekly runs as a daily schedule; the job's "needed" says no on the other six days.
        jobScheduleSave($conn, 'backup', $mode === 'off' ? 'off' : 'daily', null, $mode === 'off' ? null : $time, $by);
    }

    /**
     * The latest runs, newest first; null when the table does not exist yet (Database
     * Verification has not run) - never an empty list that would claim "no backups".
     */
    public static function runs(PDO $conn, int $limit = 50): ?array
    {
        try {
            $running = self::isRunning($conn);
            $s = $conn->prepare("SELECT r.id, r.kind, r.status, r.set_name, r.started_at, r.finished_at, r.size_bytes, r.files_total,
                                        r.files_new, r.db_bytes, r.error_text, r.warning_text, r.verify_status, r.verified_at, r.verify_detail,
                                        a.full_name AS started_by_name, v.full_name AS verified_by_name
                                   FROM backup_runs r
                                   LEFT JOIN analysts a ON a.id = r.started_by
                                   LEFT JOIN analysts v ON v.id = r.verified_by
                                  ORDER BY r.id DESC LIMIT " . max(1, min(500, $limit)));
            $s->execute();
            $rows = $s->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            if ($e->getCode() === '42S02') return null;
            throw $e;
        }
        // A process that was killed (server restart, out of memory, a web server timeout during
        // Verify) never records its end: say so rather than "running" for ever.
        $verifyCutoff = gmdate('Y-m-d H:i:s', time() - self::VERIFY_STALE_SECONDS);
        foreach ($rows as &$r) {
            if ($r['status'] === 'running' && !$running) $r['status'] = 'interrupted';
            if ($r['verify_status'] === 'running' && (string)$r['verified_at'] < $verifyCutoff) $r['verify_status'] = 'interrupted';
        }
        unset($r);
        return $rows;
    }

    /** Starts a backup in the background (it can take hours); the page follows it in the run list. */
    public static function backupNow(PDO $conn, int $by): void
    {
        if (backupTargetConfig($conn) === null || backupKeyring($conn) === null) throw new BackupsInputError('err_not_set_up');
        if (self::isRunning($conn)) throw new BackupsInputError('err_running');
        require_once __DIR__ . '/../intune.php';   // intuneFindPhpExe(): the PHP the scheduler fallback uses
        $script = realpath(__DIR__ . '/../../cron/backup.php');
        $php = intuneFindPhpExe(jobSetting($conn, 'intune_php_exe') ?: null);
        if (!$script || !jobSchedulerSpawn($php, $script, ['--manual', '--by=' . $by])) throw new BackupsInputError('err_spawn');
    }

    /**
     * Decrypts the backup of run $runId and checks every checksum (System -> Backups -> Verify).
     * Runs in the request: the passphrase must never be stored or put on a command line.
     * The result is recorded on the run, so a browser that gives up waiting still sees it.
     *
     * @return array{ok: bool, checked: int, errors: string[]}
     */
    public static function verify(PDO $conn, int $runId, string $passphrase, int $by): array
    {
        require_once __DIR__ . '/../backup/restore.php';
        $s = $conn->prepare("SELECT set_name, status FROM backup_runs WHERE id = ?");
        $s->execute([$runId]);
        $run = $s->fetch(PDO::FETCH_ASSOC);
        if (!$run || $run['status'] !== 'ok' || (string)$run['set_name'] === '') throw new BackupsInputError('err_verify_not_ok');
        $cfg = backupTargetConfig($conn);
        $kr  = backupKeyring($conn);
        if ($cfg === null || $kr === null) throw new BackupsInputError('err_not_set_up');
        try {
            backupUnlockKeyring($kr, $passphrase);   // say "wrong passphrase" before anything is marked running
        } catch (BackupWrongPassphrase $e) {
            throw new BackupsInputError('err_passphrase_wrong');
        }
        $conn->prepare("UPDATE backup_runs SET verify_status = 'running', verified_at = UTC_TIMESTAMP(), verified_by = ?, verify_detail = NULL WHERE id = ?")
             ->execute([$by, $runId]);
        // Keep going if the browser gives up, and record a fatal stop (PHP's time limit) as a failure.
        ignore_user_abort(true);
        @set_time_limit(0);
        $finished = false;
        register_shutdown_function(function () use ($conn, $runId, &$finished) {
            if ($finished) return;
            try {
                $conn->prepare("UPDATE backup_runs SET verify_status = 'failed', verify_detail = ? WHERE id = ? AND verify_status = 'running'")
                     ->execute(['Verification stopped before it finished (the server ended it). Try again.', $runId]);
            } catch (Throwable $e) {
                // the page shows it as interrupted after a while
            }
        });
        try {
            $r = backupVerifySet(backupTargetDriver($cfg), (string)$run['set_name'], $passphrase);
        } catch (BackupWrongPassphrase $e) {
            $r = ['ok' => false, 'checked' => 0, 'errors' => ['The passphrase does not open this backup (it was made with another keyring).']];
        } catch (Throwable $e) {
            $r = ['ok' => false, 'checked' => 0, 'errors' => [$e->getMessage()]];
        }
        $detail = $r['ok'] ? 'Files checked: ' . $r['checked'] : implode("\n", array_slice($r['errors'], 0, 50));
        $conn->prepare('UPDATE backup_runs SET verify_status = ?, verified_at = UTC_TIMESTAMP(), verify_detail = ? WHERE id = ?')
             ->execute([$r['ok'] ? 'ok' : 'failed', $detail, $runId]);
        $finished = true;
        return $r;
    }

    /** What the administrator types to confirm a restore (shown on the page as it is, in every language). */
    public const RESTORE_CONFIRM = 'RESTORE';

    /**
     * Opens the backup of run $runId with the passphrase and says what restoring it means:
     * when it was made, by which version, how much it holds, and whether its encryption
     * key differs from this install's (it would replace it). Changes nothing.
     *
     * @return array{run_id: int, set: string, created_at: ?string, app_version: ?string, files: int, size: ?int, key_differs: bool}
     */
    public static function restoreCheck(PDO $conn, int $runId, string $passphrase): array
    {
        require_once __DIR__ . '/../backup/restore.php';
        $s = $conn->prepare("SELECT set_name, status, kind, size_bytes FROM backup_runs WHERE id = ?");
        $s->execute([$runId]);
        $run = $s->fetch(PDO::FETCH_ASSOC);
        if (!$run || $run['status'] !== 'ok' || $run['kind'] === 'restore' || (string)$run['set_name'] === '') throw new BackupsInputError('err_restore_not_ok');
        $cfg = backupTargetConfig($conn);
        if ($cfg === null || backupKeyring($conn) === null) throw new BackupsInputError('err_not_set_up');
        if (!backupSodiumAvailable()) throw new BackupsInputError('err_sodium');
        $t = backupTargetDriver($cfg);
        try {
            $open = backupOpenSet($t, (string)$run['set_name'], $passphrase);
        } catch (BackupWrongPassphrase $e) {
            throw new BackupsInputError('err_passphrase_wrong');
        } catch (Throwable $e) {
            error_log('[backups] restore check: ' . $e->getMessage());
            throw new BackupsInputError('err_restore_unreadable');
        }
        // Only the CURRENT passphrase: an older one can still open an older backup, but not the
        // safety backup taken first, which a failed restore must be able to put back.
        try {
            sodium_memzero(backupUnlockKeyring(backupKeyring($conn), $passphrase)['secret']);
        } catch (BackupWrongPassphrase $e) {
            sodium_memzero($open['keys']['secret']);
            throw new BackupsInputError('err_restore_old_passphrase');
        }
        try {
            $key = trim(backupDecryptString(backupReadString($t, 'sets/' . $run['set_name'] . '/key.bin'), $open['datakey']));
        } catch (Throwable $e) {
            throw new BackupsInputError('err_restore_unreadable');
        } finally {
            sodium_memzero($open['keys']['secret']);
        }
        $current = is_file(ENCRYPTION_KEY_PATH) ? trim((string)file_get_contents(ENCRYPTION_KEY_PATH)) : '';
        $m = $open['manifest'];
        return [
            'run_id'      => $runId,
            'set'         => (string)$run['set_name'],
            'created_at'  => isset($m['created_at']) && strtotime((string)$m['created_at']) ? gmdate('Y-m-d H:i:s', strtotime((string)$m['created_at'])) : null,   // UTC, as the page's dates
            'app_version' => isset($m['app_version']) ? (string)$m['app_version'] : null,
            'files'       => count((array)($m['files'] ?? [])),
            'size'        => $run['size_bytes'] !== null ? (int)$run['size_bytes'] : null,
            'key_differs' => !hash_equals($current, $key),
        ];
    }

    /**
     * Starts a rollback to the backup of run $runId: switches maintenance mode on and starts
     * cron/backup_rollback.php in the background, handing it the passphrase on its standard
     * input (never stored, never on a command line). Returns the one-time token for the
     * administrator's browser, which then follows the progress.
     */
    public static function restoreStart(PDO $conn, int $runId, string $passphrase, string $confirm, int $by): string
    {
        require_once __DIR__ . '/../backup/maintenance.php';
        if ($confirm !== self::RESTORE_CONFIRM) throw new BackupsInputError('err_restore_confirm');
        if (backupMaintenanceActive()) throw new BackupsInputError('err_maintenance_on');
        if (self::isRunning($conn)) throw new BackupsInputError('err_running');
        if (backupSetting($conn, 'files_storage_previous') !== '') throw new BackupsInputError('err_storage_moving');
        $check = self::restoreCheck($conn, $runId, $passphrase);

        $script = realpath(__DIR__ . '/../../cron/backup_rollback.php');
        require_once __DIR__ . '/../intune.php';   // intuneFindPhpExe(): the PHP the scheduler fallback uses
        $php = intuneFindPhpExe(jobSetting($conn, 'intune_php_exe') ?: null);
        try {
            $token = backupMaintenanceStart($by, $check['set']);
        } catch (RuntimeException $e) {
            error_log('[backups] restore: ' . $e->getMessage());
            throw new BackupsInputError(backupMaintenanceActive() ? 'err_maintenance_on' : 'err_maintenance_folder');
        }
        if (!$script || !self::spawnWithInput($php, $script, ['--set=' . $check['set'], '--by=' . $by], $passphrase . "\n")) {
            backupMaintenanceEnd(['state' => 'failed', 'error' => 'The restore could not be started on the server.']);
            throw new BackupsInputError('err_spawn');
        }
        return $token;
    }

    /** The outcome of the last rollback, for the page (nothing secret). */
    public static function lastRestore(): ?array
    {
        require_once __DIR__ . '/../backup/maintenance.php';
        $l = backupMaintenanceLast();
        if ($l === null) return null;
        return ['state' => (string)($l['state'] ?? ''), 'set' => $l['set'] ?? null, 'safety_set' => $l['safety_set'] ?? null,
                'error' => $l['error'] ?? null, 'ended_at' => $l['ended_at'] ?? null, 'warnings' => array_slice((array)($l['warnings'] ?? []), 0, 20)];
    }

    /**
     * Starts $script in the background with $input on its standard input, and returns at
     * once. The input never appears on a command line or in the environment.
     */
    private static function spawnWithInput(string $php, string $script, array $args, string $input): bool
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $p = @proc_open(array_merge([$php, $script], $args), [0 => ['pipe', 'r'], 1 => ['file', 'NUL', 'w'], 2 => ['file', 'NUL', 'w']],
                            $pipes, null, null, ['bypass_shell' => true]);
            if (!is_resource($p)) return false;
            fwrite($pipes[0], $input);
            fclose($pipes[0]);
            return true;   // not proc_close(): that would wait for the restore to finish
        }
        // TRAP: sh gives a background job /dev/null as its input BEFORE its own redirections,
        // so "<&0" would copy /dev/null. The pipe is moved to fd 3 first and handed on from
        // there. The shell returns at once; the job carries on without it.
        $cmd = 'exec 3<&0; nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . implode(' ', array_map('escapeshellarg', $args))
             . ' <&3 > /dev/null 2>&1 &';
        $p = @proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($p)) return false;
        fwrite($pipes[0], $input);
        fclose($pipes[0]);
        return proc_close($p) === 0;
    }

    // ── internals ──

    private static function checkNewPassphrase(string $pass, string $confirm): void
    {
        if (mb_strlen($pass) < self::PASSPHRASE_MIN) throw new BackupsInputError('err_passphrase_short');
        if (!hash_equals($pass, $confirm)) throw new BackupsInputError('err_passphrase_mismatch');
    }

    /** A validated target configuration from the page's input. */
    private static function targetFromInput(array $in, ?PDO $conn): array
    {
        $type = (string)($in['type'] ?? '');
        if ($type === 'folder') {
            $folder = rtrim(trim(str_replace('\\', '/', (string)($in['folder'] ?? ''))), '/');
            if ($folder === '' || !preg_match('#^(/|[A-Za-z]:/)#', $folder) || str_contains($folder, '..')) {
                throw new BackupsInputError('err_folder_absolute');
            }
            $app  = rtrim(str_replace('\\', '/', (string)(realpath(dirname(__DIR__, 2)) ?: dirname(__DIR__, 2))), '/');
            $real = is_dir($folder) ? rtrim(str_replace('\\', '/', (string)realpath($folder)), '/') : $folder;
            foreach ([$folder, $real] as $f) {
                if (strcasecmp($f, $app) === 0 || stripos($f . '/', $app . '/') === 0) throw new BackupsInputError('err_folder_inside_app');
            }
            return ['type' => 'folder', 'folder' => $folder];
        }
        if ($type === 's3') {
            if (!extension_loaded('curl')) throw new BackupsInputError('err_curl');
            $s = (array)($in['s3'] ?? []);
            $secret = (string)($s['secret'] ?? '');
            if ($conn !== null) {
                $stored = settingGetDecrypted($conn, 'backup_s3_secret');
                if (FilesStorageService::secretUnchanged($secret, $stored)) $secret = $stored;
            }
            $cfg = [
                'type'          => 's3',
                'endpoint'      => self::endpoint((string)($s['endpoint'] ?? '')),
                'region'        => trim((string)($s['region'] ?? '')) ?: 'us-east-1',
                'bucket'        => trim((string)($s['bucket'] ?? '')),
                'access_key_id' => trim((string)($s['access_key_id'] ?? '')),
                'secret'        => $secret,
                'prefix'        => s3NormalisePrefix((string)($s['prefix'] ?? '')),
                'path_style'    => !empty($s['path_style']),
            ];
            if ($cfg['endpoint'] === '' || $cfg['bucket'] === '' || $cfg['access_key_id'] === '' || $cfg['secret'] === '') {
                throw new BackupsInputError('err_s3_incomplete');
            }
            return $cfg;
        }
        throw new BackupsInputError('err_target_type');
    }

    private static function endpoint(string $e): string
    {
        if (trim($e) === '') return '';
        try {
            return s3NormaliseEndpoint($e);
        } catch (InvalidArgumentException $ex) {
            throw new BackupsInputError('err_s3_endpoint');
        }
    }
}
