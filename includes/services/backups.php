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
require_once __DIR__ . '/../backup/notify.php';
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
    /** Watchtower asks for a Verify when none has passed for this many days (W7). */
    public const VERIFY_DUE_DAYS = 30;

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
        self::withSettingsLock($conn, fn() => self::saveTargetLocked($conn, $in, $by));
    }

    private static function saveTargetLocked(PDO $conn, array $in, int $by): void
    {
        $cfg = self::targetFromInput($in, $conn);
        if (self::isRunning($conn)) throw new BackupsInputError('err_running');
        if (!self::test($in, $conn)['ok']) throw new BackupsInputError('err_target_test');
        $keyring = backupKeyring($conn);
        if ($keyring !== null) backupWriteKeyring(backupTargetDriver($cfg), $keyring);
        $before = backupTargetConfig($conn);

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
        // A copy of everything now goes somewhere else (wiki N2): tell the people concerned.
        if ($before !== $cfg) {
            $what = $before !== null && backupTargetLabel($before) === backupTargetLabel($cfg)
                ? backupT('n_target_details', ['target' => backupTargetLabel($cfg), 'who' => self::who($conn, $by)])
                : backupT('n_target_changed', ['target' => backupTargetLabel($cfg), 'before' => backupTargetLabel($before), 'who' => self::who($conn, $by)]);
            backupNotify($conn, 'changed', backupT('n_target_title'), $what, $by);
        }
    }

    /** First-time passphrase: creates the keypair, the pool name key and this install's id. */
    public static function setPassphrase(PDO $conn, string $pass, string $confirm, int $by): void
    {
        self::withSettingsLock($conn, fn() => self::setPassphraseLocked($conn, $pass, $confirm, $by));
    }

    private static function setPassphraseLocked(PDO $conn, string $pass, string $confirm, int $by): void
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
        backupNotify($conn, 'changed', backupT('n_pass_set_title'), backupT('n_pass_set', ['who' => self::who($conn, $by)]), $by);
    }

    /**
     * A new passphrase, and with it a new keypair for everything backed up from now on
     * (backupChangeKeyring()): the old passphrase opens nothing made after the change. The new
     * one opens every backup; the old one still opens the backups made before, and the pooled
     * files those hold.
     */
    public static function changePassphrase(PDO $conn, string $old, string $new, string $confirm, int $by): void
    {
        self::withSettingsLock($conn, function () use ($conn, $old, $new, $confirm, $by) {
            $kr = backupKeyring($conn);
            if ($kr === null) throw new BackupsInputError('err_no_passphrase');
            self::checkNewPassphrase($new, $confirm);
            $ticket = self::throttleKdf($conn, $by, 'check');
            $wrong = false;
            try {
                $re = backupChangeKeyring($kr, $old, $new);
            } catch (BackupWrongPassphrase $e) {
                $wrong = true;   // the reservation stays: it counts as a wrong passphrase
                throw new BackupsInputError('err_passphrase_wrong');
            } finally {
                if (!$wrong) self::kdfRelease($conn, $ticket);
            }
            $cfg = backupTargetConfig($conn);
            if ($cfg !== null) {
                try {
                    backupWriteKeyring(backupTargetDriver($cfg), $re['keyring']);   // the old keyring is kept beside it
                } catch (Throwable $e) {
                    throw new BackupsInputError('err_target_unreachable');
                }
            }
            backupSaveSetting($conn, 'backup_keyring', json_encode($re['keyring']));
            backupSaveSetting($conn, 'backup_public_key', $re['public']);
        });
        backupNotify($conn, 'changed', backupT('n_pass_changed_title'), backupT('n_pass_changed', ['who' => self::who($conn, $by)]), $by);
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
        $before = self::scheduleLabel($conn);

        backupSaveSetting($conn, 'backup_schedule', $mode);
        backupSaveSetting($conn, 'backup_weekday', $mode === 'weekly' ? (string)$weekday : null);
        backupSaveSetting($conn, 'backup_time', $mode === 'off' ? null : $time);
        backupSaveSetting($conn, 'backup_keep_count', (string)$keep);
        // Weekly runs as a daily schedule; the job's "needed" says no on the other six days.
        jobScheduleSave($conn, 'backup', $mode === 'off' ? 'off' : 'daily', null, $mode === 'off' ? null : $time, $by);
        $after = self::scheduleLabel($conn);
        if ($after !== $before) {
            backupNotify($conn, 'changed', backupT($mode === 'off' ? 'n_schedule_off_title' : 'n_schedule_title'),
                backupT('n_schedule', ['after' => $after, 'before' => $before, 'who' => self::who($conn, $by)]), $by);
        }
    }

    /** The schedule and keep count as people read them, e.g. "weekly on Sunday at 02:00, keep 7". */
    private static function scheduleLabel(PDO $conn): string
    {
        $mode = self::scheduleMode($conn);
        $keep = self::keepCount($conn);
        if ($mode === 'off') return backupT('label_off', ['keep' => $keep]);
        $time = backupSetting($conn, 'backup_time');
        if ($mode === 'daily') return backupT('label_daily', ['time' => $time, 'keep' => $keep]);
        $day = ['', 'day_mon', 'day_tue', 'day_wed', 'day_thu', 'day_fri', 'day_sat', 'day_sun'][(int)backupSetting($conn, 'backup_weekday', '0')] ?? '';
        return backupT('label_weekly', ['day' => $day !== '' ? backupT($day) : '?', 'time' => $time, 'keep' => $keep]);
    }

    /** An analyst's name for a message, or "someone" when the id names nobody. */
    private static function who(PDO $conn, int $id): string
    {
        $s = $conn->prepare('SELECT full_name FROM analysts WHERE id = ?');
        $s->execute([$id]);
        $n = trim((string)$s->fetchColumn());
        return $n !== '' ? $n : 'someone';
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
        $ticket = self::throttleKdf($conn, $by, 'check');
        $wrong = false;
        try {
            $unlocked = backupUnlockKeyring($kr, $passphrase);   // say "wrong passphrase" before anything is marked running
            backupForgetKeys($unlocked);
        } catch (BackupWrongPassphrase $e) {
            $wrong = true;   // the reservation stays: it counts as a wrong passphrase
            throw new BackupsInputError('err_passphrase_wrong');
        } finally {
            if (!$wrong) self::kdfRelease($conn, $ticket);
        }
        // One Verify at a time, and pruning (which could remove what is being read) waits for it.
        if (!self::verifyLock($conn)) throw new BackupsInputError('err_verify_running');
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
        // A passed check can still carry a warning (an older backup's dump without an end record): on its own line.
        $detail = $r['ok'] ? implode("\n", array_merge(['Files checked: ' . $r['checked']], $r['warnings'] ?? []))
                           : implode("\n", array_slice($r['errors'], 0, 50));
        $conn->prepare('UPDATE backup_runs SET verify_status = ?, verified_at = UTC_TIMESTAMP(), verify_detail = ? WHERE id = ?')
             ->execute([$r['ok'] ? 'ok' : 'failed', $detail, $runId]);
        $finished = true;
        $conn->prepare('SELECT RELEASE_LOCK(?)')->execute([backupVerifyLockName($conn)]);
        if (!$r['ok']) {
            // A backup that does not check out may not restore (wiki N2). Not the person who ran Verify: they see it.
            backupNotify($conn, 'failed', backupT('n_verify_failed_title'), backupT('n_verify_failed', ['set' => $run['set_name'],
                         'errors' => implode('; ', array_slice($r['errors'], 0, 3)), 'who' => self::who($conn, $by)]), $by, $runId);
        }
        return $r;
    }

    /**
     * May this analyst open System -> Backups? An administrator, or a holder of Storage and
     * backups who can open Files - the same rule as the page and the API.
     */
    public static function mayOpen(PDO $conn, int $analystId): bool
    {
        if (analystIsAdmin($conn, $analystId)) return true;
        require_once __DIR__ . '/../rbac.php';
        return analystHasCapability($conn, $analystId, Cap::FILES_STORAGE_BACKUPS) && analystCanAccessModule($conn, $analystId, 'files');
    }

    /**
     * What is wrong with backups, for Watchtower (wiki Storage-Series-Follow-Ups W6, W7); [] when
     * nothing is - or backups were never set up (an install that does not use them sees nothing).
     *
     *   last_failed      the last backup failed, or was interrupted                      (red)
     *   overdue          no backup within its schedule plus a day (since the last one,
     *                    or since the schedule was set when there has been none)          (red)
     *   verify_failed    the last Verify found a problem                                 (red)
     *   never_verified   there are backups, but none has ever been checked with Verify   (amber)
     *
     * @param int|null $now  a Unix time (tests)
     * @return array<int, array{key: string, severity: string, params: array}>
     */
    public static function attention(PDO $conn, ?int $now = null): array
    {
        $now ??= time();
        if (backupTargetConfig($conn) === null || backupKeyring($conn) === null) return [];
        try {
            $runs = $conn->query("SELECT id, status, started_at, finished_at, error_text, verify_status, verified_at
                                    FROM backup_runs WHERE kind IN ('scheduled', 'manual') ORDER BY id DESC LIMIT 200")->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            if ($e->getCode() === '42S02') return [];   // no history table yet: System -> Backups says so
            throw $e;                                   // a failed lookup is not an answer (Watchtower says so)
        }
        $out = [];
        $running = self::isRunning($conn);
        $last = null;
        foreach ($runs as $r) {
            if ($r['status'] === 'running' && $running) continue;   // the one in progress: judged when it ends
            $last = $r;
            break;
        }
        if ($last !== null && $last['status'] !== 'ok') {
            $out[] = ['key' => 'last_failed', 'severity' => 'red',
                      'params' => ['when' => (string)$last['started_at'], 'error' => $last['status'] === 'running' ? null : (string)$last['error_text']]];   // null: interrupted
        }
        $mode = self::scheduleMode($conn);
        if ($mode !== 'off') {
            $lastOk = null;
            foreach ($runs as $r) if ($r['status'] === 'ok') { $lastOk = (string)($r['finished_at'] ?: $r['started_at']); break; }
            $since = $lastOk;
            if ($since === null) {
                $s = $conn->query("SELECT updated_datetime FROM job_schedules WHERE job_key = 'backup'")->fetchColumn();
                $since = $s ? (string)$s : null;
            }
            $allowed = ($mode === 'weekly' ? 7 : 1) * 86400 + 86400;   // its schedule, plus a day
            if ($since !== null && $now - strtotime($since . ' UTC') > $allowed) {
                $out[] = ['key' => 'overdue', 'severity' => 'red', 'params' => ['since' => $since, 'never' => $lastOk === null]];
            }
        }
        $lastVerify = null;
        $everVerified = false;
        $anyOk = false;
        foreach ($runs as $r) {
            if ($r['status'] === 'ok') $anyOk = true;
            if ($r['verify_status'] === 'ok') $everVerified = true;
            if (in_array($r['verify_status'], ['ok', 'failed'], true)
                && ($lastVerify === null || (string)$r['verified_at'] > (string)$lastVerify['verified_at'])) $lastVerify = $r;   // the latest check, of any backup
        }
        if ($lastVerify !== null && $lastVerify['verify_status'] === 'failed') {
            $out[] = ['key' => 'verify_failed', 'severity' => 'red', 'params' => ['when' => (string)$lastVerify['verified_at']]];
        } elseif ($anyOk && !$everVerified) {
            $out[] = ['key' => 'never_verified', 'severity' => 'amber', 'params' => []];
        } elseif ($lastVerify !== null && $now - strtotime($lastVerify['verified_at'] . ' UTC') > self::VERIFY_DUE_DAYS * 86400) {
            // A backup only says its stored files are there at the right size; Verify reads them through.
            $out[] = ['key' => 'verify_stale', 'severity' => 'amber', 'params' => ['when' => (string)$lastVerify['verified_at'], 'days' => self::VERIFY_DUE_DAYS]];
        }
        return $out;
    }

    // ── internals ──

    /** At most this many WRONG passphrases per analyst and kind of check, per window. */
    public static int $kdfLimit = 10;   // tests change it
    public const KDF_WINDOW_SECONDS = 300;

    /**
     * Reserves one passphrase check (Argon2id per keyring tried: slow and memory-hungry on purpose), or
     * refuses it when this analyst already has $kdfLimit wrong passphrases - and checks still running -
     * for this kind of check in the last KDF_WINDOW_SECONDS. Checked and reserved under the settings
     * lock, so requests sent in parallel cannot all slip past the count. A check that turns out right
     * gives its reservation back (kdfRelease()); a wrong one keeps it, so only wrong passphrases count.
     * Per analyst, and restores ('restore') counted apart from Verify and passphrase changes ('check'):
     * someone guessing cannot lock anyone else out, nor an administrator out of a restore.
     *
     * @return array{0: string, 1: string}  the reservation, for kdfRelease()
     */
    private static function throttleKdf(PDO $conn, int $by, string $kind): array
    {
        $slot = $kind . ':' . $by;
        $ticket = time() . ':' . bin2hex(random_bytes(6));
        self::withSettingsLock($conn, function () use ($conn, $slot, $ticket) {
            $all = self::kdfFailures($conn);
            if (count($all[$slot] ?? []) >= self::$kdfLimit) throw new BackupsInputError('err_throttled');
            $all[$slot][] = $ticket;
            backupSaveSetting($conn, 'backup_kdf_failures', json_encode($all));
        });
        return [$slot, $ticket];
    }

    /** Gives back a reservation (throttleKdf()): the passphrase was right, or it was never checked. */
    private static function kdfRelease(PDO $conn, array $reservation): void
    {
        [$slot, $ticket] = $reservation;
        self::withSettingsLock($conn, function () use ($conn, $slot, $ticket) {
            $all = self::kdfFailures($conn);
            $all[$slot] = array_values(array_diff($all[$slot] ?? [], [$ticket]));
            if (!$all[$slot]) unset($all[$slot]);
            backupSaveSetting($conn, 'backup_kdf_failures', json_encode($all));
        });
    }

    /** @return array<string, string[]>  "<kind>:<analyst id>" => "<time>:<id>" of wrong (or running) checks within the window */
    private static function kdfFailures(PDO $conn): array
    {
        $now = time();
        $out = [];
        foreach ((array)json_decode(backupSetting($conn, 'backup_kdf_failures', '{}'), true) as $k => $entries) {
            $recent = array_values(array_filter((array)$entries, fn($e) => is_string($e) && (int)$e > $now - self::KDF_WINDOW_SECONDS));
            if ($recent) $out[(string)$k] = $recent;
        }
        return $out;
    }

    /** Holds the Verify lock for this request: pruning skips while a Verify reads a backup. */
    private static function verifyLock(PDO $conn): bool
    {
        $s = $conn->prepare('SELECT GET_LOCK(?, 0)');
        $s->execute([backupVerifyLockName($conn)]);
        return (int)$s->fetchColumn() === 1;
    }

    /**
     * Runs $fn holding the backup settings lock, so two people saving the target or the passphrase
     * at once cannot interleave their checks and writes (two first-time keyrings, a keyring written to
     * one target and saved against another).
     */
    private static function withSettingsLock(PDO $conn, callable $fn): void
    {
        $name = 'freeitsm_backup_settings_' . substr(sha1((string)$conn->query('SELECT DATABASE()')->fetchColumn()), 0, 16);
        $s = $conn->prepare('SELECT GET_LOCK(?, 10)');
        $s->execute([$name]);
        if ((int)$s->fetchColumn() !== 1) throw new BackupsInputError('err_busy');
        try {
            $fn();
        } finally {
            $conn->prepare('SELECT RELEASE_LOCK(?)')->execute([$name]);
        }
    }

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
