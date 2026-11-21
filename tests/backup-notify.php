<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * Being told about backups (#286, wiki Storage-Series-Follow-Ups N2): a changed target,
 * passphrase or schedule, and a failed backup or Verify, ring the bell and email every
 * active administrator and every holder of Storage and backups who can open Files - never
 * the person who did it. A backup that works tells nobody.
 *
 * ZZ analysts, a ZZ role, settings and notifications in one transaction that is rolled back;
 * the failed backup (which refuses to run inside a transaction) is cleaned up by id. Never
 * emails anyone: BackupNotify::$mailer records instead.
 *   FREEITSM_TEST_DATABASE=<throwaway db> php tests/backup-notify.php
 */

$root = dirname(__DIR__);
require_once "$root/config.php";
require_once "$root/includes/functions.php";
require_once "$root/includes/entity_links.php";
require_once "$root/includes/i18n.php";
require_once "$root/includes/rbac.php";
require_once "$root/includes/services/notifications.php";
require_once "$root/includes/services/backups.php";
require_once "$root/includes/backup/runner.php";
require_once "$root/includes/backup/notify.php";
$zzMails = [];
BackupNotify::$mailer = function (string $to, string $subject, string $html) use (&$zzMails): void { $zzMails[] = [$to, $subject, $html]; };

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  PASS  {$what}\n"; }
    else       { $fail++; echo "  FAIL  {$what}" . ($detail !== '' ? "  <- {$detail}" : '') . "\n"; }
}

/** A target that cannot be reached: every backup to it fails. */
final class ZzBnDownTarget implements StorageDriver, StorageLister
{
    private function down(): never { throw new StorageUnavailable('Storage could not be reached: test target is down'); }
    public function putFile(string $key, string $localPath, bool $move = false): void { $this->down(); }
    public function readRange(string $key, int $start, int $end, callable $sink): void { $this->down(); }
    public function readTo(string $key, string $localPath): void { $this->down(); }
    public function size(string $key): ?int { $this->down(); }
    public function delete(string $key): void { $this->down(); }
    public function label(): string { return 'zz-down'; }
    public function listKeys(string $prefix): array { $this->down(); }
    public function listObjects(string $prefix): array { $this->down(); }
    public function eachObject(string $prefix, callable $fn): void { $this->down(); }
}

echo "\nBackups tell the people concerned\n" . str_repeat('=', 72) . "\n";
$conn = connectToDatabase();
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
if (getenv('FREEITSM_TEST_DATABASE') !== (string)$conn->query('SELECT DATABASE()')->fetchColumn()) {
    exit("Set FREEITSM_TEST_DATABASE to the throwaway database config.php points at - this test writes (rolled back).\n");
}

$types = NotificationsService::types();
foreach (['backup.changed', 'backup.failed'] as $t) {
    ok("a notification type $t, on by default", ($types[$t]['default'] ?? null) === true, json_encode($types[$t] ?? null));
    foreach (["common.notifications.pref.$t", "common.notifications.event.$t"] as $k) ok("...with a label: $k", t($k) !== $k && t($k) !== '');
}
ok('...linking to System -> Backups', entityLink('backup', 7) === 'system/backups/', var_export(entityLink('backup', 7), true));

$tag = 'ZZbn' . bin2hex(random_bytes(3));
$bells = function (int $who, ?string $type = null) use ($conn, &$startId): array {
    $s = $conn->prepare("SELECT event_type, title, body, event_count FROM notifications WHERE analyst_id = ? AND entity_type = 'backup' AND id > ?"
                        . ($type ? ' AND event_type = ?' : '') . ' ORDER BY id');
    $s->execute($type ? [$who, $startId, $type] : [$who, $startId]);
    return $s->fetchAll(PDO::FETCH_ASSOC);
};
$mailsTo = function (string $email) use (&$zzMails): array { return array_values(array_filter($zzMails, fn($m) => $m[0] === $email)); };

$work = str_replace('\\', '/', sys_get_temp_dir()) . '/zz-bn-' . bin2hex(random_bytes(4));
mkdir($work);
$startId = (int)$conn->query('SELECT COALESCE(MAX(id), 0) FROM notifications')->fetchColumn();
$conn->beginTransaction();
try {
    $mk = function (string $name, int $admin, int $active = 1) use ($conn, $tag): int {
        $conn->prepare("INSERT INTO analysts (username, password_hash, full_name, email, is_active, is_admin, can_access_all_modules, created_datetime)
                        VALUES (?, 'x', ?, ?, ?, ?, 1, UTC_TIMESTAMP())")
             ->execute([strtolower("$tag$name"), "$tag $name", strtolower("$tag-$name@example.invalid"), $active, $admin]);
        return (int)$conn->lastInsertId();
    };
    $actor    = $mk('actor', 1);
    $admin    = $mk('admin', 1);
    $holder   = $mk('holder', 0);
    $umbrella = $mk('umbrella', 0);
    $noFiles  = $mk('nofiles', 0);
    $gone     = $mk('gone', 1, 0);
    $conn->prepare('UPDATE analysts SET can_access_all_modules = 0 WHERE id = ?')->execute([$noFiles]);
    $conn->prepare("INSERT INTO analyst_modules (analyst_id, module_key) VALUES (?, 'tickets')")->execute([$noFiles]);
    $role = function (string $cap) use ($conn, $tag): int {
        $conn->prepare('INSERT INTO rbac_roles (name, is_active) VALUES (?, 1)')->execute(["$tag $cap"]);
        $id = (int)$conn->lastInsertId();
        $conn->prepare('INSERT INTO rbac_role_capabilities (role_id, capability_key) VALUES (?, ?)')->execute([$id, $cap]);
        return $id;
    };
    $sbRole = $role(capKey(Cap::FILES_STORAGE_BACKUPS));
    $umRole = $role(capKey(Cap::FILES_MANAGE));
    foreach ([[$holder, $sbRole], [$noFiles, $sbRole], [$umbrella, $umRole]] as [$a, $r]) {
        $conn->prepare('INSERT INTO rbac_analyst_roles (analyst_id, role_id) VALUES (?, ?)')->execute([$a, $r]);
    }

    $ids = array_column(backupNotifyRecipients($conn), 'id');
    ok('told: active administrators', in_array($actor, $ids, true) && in_array($admin, $ids, true));
    ok('told: a holder of Storage and backups', in_array($holder, $ids, true));
    ok('not told: "Manage everything in Files" only', !in_array($umbrella, $ids, true));
    ok('not told: a holder who cannot open Files (nor System -> Backups)', !in_array($noFiles, $ids, true));
    ok('not told: an inactive administrator', !in_array($gone, $ids, true));

    $prefs = fn(int $id) => array_keys(NotificationsService::effectivePreferences($conn, $id));
    ok('Preferences offers the backup alerts to a holder and an administrator', in_array('backup.failed', $prefs($holder), true) && in_array('backup.changed', $prefs($admin), true));
    ok('...and not to anyone who could never get them', !in_array('backup.changed', $prefs($umbrella), true));

    // The settings: target, schedule (the passphrase is covered the same way, by the same call).
    foreach (['backup_target', 'backup_folder', 'backup_schedule', 'backup_weekday', 'backup_time', 'backup_keep_count'] as $k) {
        $conn->prepare('DELETE FROM system_settings WHERE setting_key = ?')->execute([$k]);
    }
    $zzMails = [];
    BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => $work], $actor);
    $b = $bells($admin, 'backup.changed');
    ok('a new target rings the bell, naming where backups now go', count($b) === 1 && str_contains($b[0]['body'], $work) && $b[0]['title'] === 'Backup target changed', json_encode($b));
    ok('...for the holder too', count($bells($holder, 'backup.changed')) === 1);
    ok('...never for the person who changed it', $bells($actor) === []);
    ok('...nor for anyone not concerned', $bells($umbrella) === [] && $bells($noFiles) === [] && $bells($gone) === []);
    ok('...and emails them (and nobody else)', count($mailsTo(strtolower("$tag-admin@example.invalid"))) === 1 && count($mailsTo(strtolower("$tag-holder@example.invalid"))) === 1
       && !$mailsTo(strtolower("$tag-actor@example.invalid")) && !$mailsTo(strtolower("$tag-umbrella@example.invalid")), json_encode(array_column($zzMails, 0)));
    $n = count($zzMails);
    BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => $work], $actor);
    ok('saving the same target again tells nobody', count($zzMails) === $n);

    BackupsService::saveSchedule($conn, 'weekly', 7, '02:30', 5, $actor);
    $b = $bells($admin, 'backup.changed');
    ok('a schedule change is told, as people read it', str_contains((string)end($b)['body'], 'weekly on Sunday at 02:30, keep 5'), json_encode(end($b)));
    $n = count($zzMails);
    BackupsService::saveSchedule($conn, 'weekly', 7, '02:30', 5, $actor);
    ok('saving the same schedule tells nobody', count($zzMails) === $n);
    BackupsService::saveSchedule($conn, 'off', null, null, 5, $actor);
    $last = end($zzMails);
    ok('switching scheduled backups off says so', $last && $last[1] === 'FreeITSM: Scheduled backups switched off', json_encode($last));

    // Each person's own switch (Preferences) holds for the email as for the bell.
    $conn->prepare("INSERT INTO user_preferences (analyst_id, preference_key, preference_value) VALUES (?, 'notification_types', ?)")
         ->execute([$holder, json_encode(['backup.changed' => false])]);
    $zzMails = [];
    BackupsService::saveSchedule($conn, 'daily', null, '01:00', 5, $actor);
    ok('someone who switched the alert off gets no email', !$mailsTo(strtolower("$tag-holder@example.invalid")) && count($mailsTo(strtolower("$tag-admin@example.invalid"))) === 1,
       json_encode(array_column($zzMails, 0)));
    $conn->prepare("DELETE FROM user_preferences WHERE analyst_id = ? AND preference_key = 'notification_types'")->execute([$holder]);

    // A passphrase change (keys made cheaply for the test).
    BackupsService::$kdfOps = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    BackupsService::$kdfMem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    foreach (['backup_public_key', 'backup_keyring', 'backup_pool_name_secret'] as $k) $conn->prepare('DELETE FROM system_settings WHERE setting_key = ?')->execute([$k]);
    BackupsService::setPassphrase($conn, 'a long test passphrase', 'a long test passphrase', $actor);
    BackupsService::changePassphrase($conn, 'a long test passphrase', 'another long passphrase', 'another long passphrase', $actor);
    $titles = array_column($mailsTo(strtolower("$tag-holder@example.invalid")), 1);
    ok('setting and changing the passphrase are told', in_array('FreeITSM: Backup passphrase set', $titles, true) && in_array('FreeITSM: Backup passphrase changed', $titles, true), json_encode($titles));
    ok('...never with the passphrase in them', !array_filter($zzMails, fn($m) => str_contains($m[2], 'long test passphrase') || str_contains($m[2], 'another long passphrase')));
} finally {
    $conn->rollBack();
}

// A failed backup (outside a transaction: a backup refuses to start inside one). Its own ZZ
// administrator is made and removed here; every row it causes is deleted by id.
$conn->prepare("INSERT INTO analysts (username, password_hash, full_name, email, is_active, is_admin, created_datetime)
                VALUES (?, 'x', ?, ?, 1, 1, UTC_TIMESTAMP())")->execute([strtolower("{$tag}fail"), "$tag fail", strtolower("$tag-fail@example.invalid")]);
$failAdmin = (int)$conn->lastInsertId();
$maxRun = (int)$conn->query('SELECT COALESCE(MAX(id), 0) FROM backup_runs')->fetchColumn();
try {
    $zzMails = [];
    $r = (new BackupRunner($conn, new ZzBnDownTarget(), $root))->run('scheduled', null);
    $b = $bells($failAdmin, 'backup.failed');
    ok('a failed backup rings the bell', $r['status'] === 'failed' && count($b) === 1 && $b[0]['title'] === 'Backup failed', json_encode([$r['error'], $b]));
    ok('...and emails', count($mailsTo(strtolower("$tag-fail@example.invalid"))) === 1);
} finally {
    $conn->prepare("DELETE FROM notifications WHERE id > ? AND entity_type = 'backup'")->execute([$startId]);
    $conn->prepare('DELETE FROM backup_runs WHERE id > ?')->execute([$maxRun]);
    $conn->prepare('DELETE FROM analysts WHERE id = ?')->execute([$failAdmin]);
    BackupRunner::rmTree($work);
}
$left = (int)$conn->query("SELECT COUNT(*) FROM analysts WHERE username LIKE " . $conn->quote(strtolower($tag) . '%'))->fetchColumn();
ok('cleanup removed everything it made', $left === 0 && is_dir($work) === false, (string)$left);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
