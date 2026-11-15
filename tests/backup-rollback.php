<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * In-app rollback (System -> Backups -> Restore): maintenance mode, the safety backup,
 * the rollback itself (database, upload folders, Files), recovery when it fails, and
 * the job started over HTTP.
 *
 * ⚠️ The rollback REPLACES the test database (it is restored from a backup this test
 * takes a moment earlier). Run it only against a scratch database, as the web server's
 * user (the job runs as that user):
 *   FREEITSM_TEST_DATABASE=<db> FREEITSM_TEST_URL=http://localhost php tests/backup-rollback.php
 */

$root = dirname(__DIR__);
require_once "$root/config.php";
require_once "$root/includes/functions.php";
require_once "$root/includes/storage/driver.php";
require_once "$root/includes/backup/crypto.php";
require_once "$root/includes/backup/target.php";
require_once "$root/includes/backup/maintenance.php";
require_once "$root/includes/services/backups.php";
require_once "$root/includes/files/storage.php";
require_once "$root/includes/backup/runner.php";
require_once "$root/includes/backup/restore.php";
require_once "$root/includes/backup/rollback.php";
require_once "$root/includes/i18n.php";

$pass = 0; $fail = 0;
function ok(string $label, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; printf("  PASS %-70s\n", $label); }
    else       { $fail++; printf("  FAIL %-70s %s\n", $label, $detail); }
}
function section(string $t): void { echo "\n$t\n" . str_repeat('-', 72) . "\n"; }

echo "\nBackups: in-app rollback\n" . str_repeat('=', 72) . "\n";

$conn = connectToDatabase();
$dbName = (string)$conn->query('SELECT DATABASE()')->fetchColumn();
if (getenv('FREEITSM_TEST_DATABASE') !== $dbName) {
    echo "\nSKIPPED: set FREEITSM_TEST_DATABASE to the database this may REPLACE (this one is $dbName).\n";
    echo "\n$pass passed, $fail failed\n";
    exit($fail ? 1 : 0);
}

$work = sys_get_temp_dir() . '/zz-rb-' . bin2hex(random_bytes(4));
mkdir($work);
$cleanup = [];
$base = rtrim(getenv('FREEITSM_TEST_URL') ?: 'http://localhost', '/') . '/';
$sessDir = rtrim(getenv('FREEITSM_SESS_DIR') ?: (ini_get('session.save_path') ?: sys_get_temp_dir()), '/\\');
$admin = (int)$conn->query('SELECT id FROM analysts ORDER BY id LIMIT 1')->fetchColumn();

$mkSess = function (int $id, string $csrf) use ($sessDir, &$cleanup): string {
    $sid = bin2hex(random_bytes(16));   // hex: a valid session id whatever the sid settings
    file_put_contents("$sessDir/sess_$sid", 'analyst_id|i:' . $id . ';csrf_token|s:' . strlen($csrf) . ':"' . $csrf . '";');
    $cleanup[] = fn() => @unlink("$sessDir/sess_$sid");
    return $sid;
};
/** @return array{0: int, 1: ?array, 2: string, 3: string} code, json, body, headers */
$http = function (string $path, ?string $cookie = null, ?array $post = null, ?string $csrf = null) use ($base): array {
    $ch = curl_init($base . $path);
    $h = ['Content-Type: application/json'];
    if ($csrf !== null) $h[] = 'X-CSRF-Token: ' . $csrf;
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 120, CURLOPT_HTTPHEADER => $h]);
    if ($cookie !== null) curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    if ($post !== null) { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post)); }
    $raw = (string)curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hs = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    $body = substr($raw, $hs);
    return [$code, json_decode($body, true), $body, substr($raw, 0, $hs)];
};
$php = PHP_BINARY;
$cli = fn(string $script, string $args = '') => trim((string)shell_exec('cd ' . escapeshellarg($root) . " && $php $script $args 2>&1; echo \"EXIT=\$?\""));

try {
    section('Maintenance mode: the file');
    $mf = backupMaintenanceFile();
    ok('it lives beside the encryption key, outside the web root', dirname($mf) === dirname(ENCRYPTION_KEY_PATH) && !str_starts_with(str_replace('\\', '/', $mf), str_replace('\\', '/', $root) . '/'), $mf);
    ok('it is named after the key file (one per install)', basename($mf) === pathinfo(ENCRYPTION_KEY_PATH, PATHINFO_FILENAME) . '.maintenance.json', basename($mf));
    ok('off to begin with', !backupMaintenanceActive() && backupMaintenanceRead() === null);
    $cleanup[] = function () use ($mf) { @unlink($mf); @unlink(backupMaintenanceLastFile()); };

    $token = backupMaintenanceStart($admin, '20261112T000000Z');
    $st = backupMaintenanceRead();
    ok('start: on, with the analyst, the set and a heartbeat', backupMaintenanceActive() && $st['by'] === $admin && $st['set'] === '20261112T000000Z'
       && $st['state'] === 'starting' && abs((int)$st['heartbeat'] - time()) < 5, json_encode($st));
    ok('start: the token is returned, only its hash is kept', strlen($token) === 64 && !str_contains((string)file_get_contents($mf), $token)
       && hash_equals((string)$st['token_hash'], hash('sha256', $token)));
    $threw = null;
    try { backupMaintenanceStart($admin, '20261112T000000Z'); } catch (Throwable $e) { $threw = $e; }
    ok('start: refused while already on', $threw instanceof RuntimeException);
    backupMaintenanceUpdate(['state' => 'restoring', 'step' => 'Restoring the database'], 'Restoring the database...');
    $st = backupMaintenanceRead();
    ok('update: state, step and a log line', $st['state'] === 'restoring' && end($st['log'])['text'] === 'Restoring the database...');
    for ($i = 0; $i < 250; $i++) backupMaintenanceUpdate([], "line $i");
    ok('update: the log keeps the latest 200 lines', count(backupMaintenanceRead()['log']) === 200 && end(backupMaintenanceRead()['log'])['text'] === 'line 249');
    ok('the file is not readable by other users', DIRECTORY_SEPARATOR === '\\' || (fileperms($mf) & 0007) === 0, decoct(fileperms($mf) & 0777));
    ok('stale: a fresh heartbeat is not stale', !backupMaintenanceStale(backupMaintenanceRead()));
    ok('stale: an old one is', backupMaintenanceStale(['heartbeat' => time() - BACKUP_MAINTENANCE_STALE - 1, 'state' => 'restoring']));
    ok('stale: "broken" (the job gave up) counts as stopped', backupMaintenanceStale(['heartbeat' => time(), 'state' => 'broken']));
    backupMaintenanceEnd(['state' => 'done', 'result' => 'ok']);
    ok('end: off, and the outcome is kept as the last restore', !backupMaintenanceActive() && (backupMaintenanceLast()['state'] ?? null) === 'done');

    section('Maintenance mode: what people see (over HTTP)');
    $csrf = bin2hex(random_bytes(16));
    $adminSid = $mkSess($admin, $csrf);
    $token = backupMaintenanceStart($admin, '20261112T000000Z');
    [$code, , $body, $hdr] = $http('index.php');
    ok('a page: 503 with the maintenance message', $code === 503 && str_contains($body, t('system.backups.mm_title')), "$code " . substr($body, 0, 120));
    ok('a page: Retry-After is sent', stripos($hdr, 'Retry-After:') !== false);
    [$code, $j] = $http('api/system/backups.php', 'PHPSESSID=' . $adminSid);
    ok('an API call (even from the restoring admin, without the token): 503 JSON', $code === 503 && ($j['maintenance'] ?? null) === true && ($j['success'] ?? null) === false, (string)$code);
    [$code, , $body] = $http('system/backups/', 'PHPSESSID=' . $adminSid . '; ' . BACKUP_MAINTENANCE_COOKIE . '=' . $token);
    ok('the restoring admin gets the progress page', $code === 503 && str_contains($body, 'backup_rollback_status.php') && str_contains($body, t('system.backups.mm_progress_title', ['set' => '20261112T000000Z'])), "$code " . substr($body, 0, 160));
    [$code, $j] = $http('api/system/backup_rollback_status.php', 'PHPSESSID=' . $adminSid . '; ' . BACKUP_MAINTENANCE_COOKIE . '=' . $token);
    ok('status: the admin with the token reads the progress', $code === 200 && ($j['state'] ?? '') === 'starting' && !isset($j['token_hash']), json_encode($j));
    [$code] = $http('api/system/backup_rollback_status.php', 'PHPSESSID=' . $adminSid);
    ok('status: without the token, 403', $code === 403, (string)$code);
    [$code] = $http('api/system/backup_rollback_status.php', BACKUP_MAINTENANCE_COOKIE . '=' . $token);
    ok('status: the token without the session, 403', $code === 403, (string)$code);
    $ownerCookie = 'PHPSESSID=' . $adminSid . '; ' . BACKUP_MAINTENANCE_COOKIE . '=' . $token;
    [$code] = $http('api/system/backup_rollback_status.php', $ownerCookie, ['action' => 'off']);
    ok('turn off: refused without the CSRF token', $code === 403, (string)$code);
    [$code] = $http('api/system/backup_rollback_status.php', $ownerCookie, ['action' => 'off'], $csrf);
    ok('turn off: refused while the job is still working', $code === 409 && backupMaintenanceActive(), (string)$code);
    backupMaintenanceUpdate(['heartbeat' => time() - BACKUP_MAINTENANCE_STALE - 5]);
    [$code, $j] = $http('api/system/backup_rollback_status.php', $ownerCookie);
    ok('status: a job that stopped is reported as stopped', $code === 200 && ($j['stopped'] ?? null) === true, json_encode($j));
    [$code] = $http('api/system/backup_rollback_status.php', $ownerCookie, ['action' => 'off'], $csrf);
    ok('turn off: allowed once the job has stopped', $code === 200 && !backupMaintenanceActive() && (backupMaintenanceLast()['state'] ?? '') === 'abandoned', (string)$code);
    [$code] = $http('index.php');
    ok('after: pages are back (not 503)', $code !== 503, (string)$code);

    section('Maintenance mode: background jobs');
    $token = backupMaintenanceStart($admin, '20261112T000000Z');
    $before = (int)$conn->query("SELECT COUNT(*) FROM job_runs")->fetchColumn();
    $out = $cli('cron/backup.php', '--manual');
    ok('a job started from cron/ does nothing and says why', str_contains($out, 'maintenance') && str_ends_with($out, 'EXIT=0'), $out);
    $out = $cli('cron/run.php');
    ok('the scheduler starts nothing', str_contains($out, 'maintenance') && str_ends_with($out, 'EXIT=0'), $out);
    ok('no job run was recorded', (int)$conn->query("SELECT COUNT(*) FROM job_runs")->fetchColumn() === $before);
    $out = $cli('scripts/db_verify_cli.php', '--quiet');
    ok('scripts/ still run (an administrator at the console)', !str_contains($out, 'maintenance'), $out);
    $out = $cli('scripts/documents_maintenance.php', '--quiet');
    ok('a scheduled job kept in scripts/ is stopped too', str_contains($out, 'maintenance') && str_ends_with($out, 'EXIT=0'), $out);
    $outside = [];
    foreach (jobRegistry() as $job => $def) {
        if (preg_match('#^php\s+(\S+\.php)#', (string)($def['command'] ?? ''), $cm) && !str_starts_with($cm[1], 'cron/')
            && !in_array($cm[1], BACKUP_MAINTENANCE_CLI_JOBS, true)) $outside[] = "$job: {$cm[1]}";
    }
    ok('every scheduled job is one maintenance mode stops', $outside === [], implode(', ', $outside));

    // Entry points that do not load functions.php still meet the gate: it runs from includes/db.php,
    // which every database connection loads (dbConnectionOptions()).
    foreach (['api/auth/request_password_reset.php', 'api/auth/reset_password.php', 'auth/oauth_callback.php', 'auth/google_oauth_callback.php'] as $p) {
        [$code] = $http($p, null, str_starts_with($p, 'api/') ? ['email' => 'zz@example.invalid'] : null);
        ok("$p: 503", $code === 503, (string)$code);
    }
    $unguarded = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        $p = str_replace('\\', '/', substr($f->getPathname(), strlen($root) + 1));
        if ($f->getExtension() !== 'php' || preg_match('#^(tests|vendor|node_modules)/#', $p)) continue;
        $src = (string)file_get_contents($f->getPathname());
        if (str_contains($src, 'new PDO(') && !str_contains($src, 'dbConnectionOptions(')) $unguarded[] = $p;
    }
    ok('every database connection goes through includes/db.php (so through the gate)', $unguarded === [], implode(', ', $unguarded));
    ok('includes/db.php runs the gate', str_contains((string)file_get_contents("$root/includes/db.php"), 'maintenance_gate.php'));
    backupMaintenanceEnd(['state' => 'abandoned']);

    section('Maintenance mode: a job that is still working is never cut off');
    $token = backupMaintenanceStart($admin, '20261112T000000Z');
    $owner2 = 'PHPSESSID=' . $adminSid . '; ' . BACKUP_MAINTENANCE_COOKIE . '=' . $token;
    $null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
    $dummy = proc_open([PHP_BINARY, '-r', 'sleep(60);', 'backup_rollback.php'], [0 => ['pipe', 'r'], 1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']], $dp);
    $dpid = (int)proc_get_status($dummy)['pid'];
    usleep(500000);   // let it get past exec: the real job records its own pid only once running
    backupMaintenanceUpdate(['pid' => $dpid, 'state' => 'restoring', 'heartbeat' => time() - BACKUP_MAINTENANCE_STALE - 60]);
    [$code, $j] = $http('api/system/backup_rollback_status.php', $owner2);
    ok('status: a quiet heartbeat with the job still alive is not "stopped"', $code === 200 && ($j['stopped'] ?? null) === false, json_encode($j));
    [$code] = $http('api/system/backup_rollback_status.php', $owner2, ['action' => 'off'], $csrf);
    ok('turn off: refused while the job is alive, however long it has been quiet', $code === 409 && backupMaintenanceActive(), (string)$code);
    $out = $cli('scripts/backup_maintenance.php', '--off');
    ok('command line off: refused while the job is alive', str_contains($out, 'still running') && !str_ends_with($out, 'EXIT=0') && backupMaintenanceActive(), $out);
    proc_terminate($dummy);
    proc_close($dummy);
    [$code, $j] = $http('api/system/backup_rollback_status.php', $owner2);
    ok('status: once the job is gone it is "stopped"', $code === 200 && ($j['stopped'] ?? null) === true, json_encode($j));
    $out = $cli('scripts/backup_maintenance.php');
    ok('command line: says what state it is in', str_contains($out, 'restoring') && str_ends_with($out, 'EXIT=0'), $out);
    $out = $cli('scripts/backup_maintenance.php', '--off');
    ok('command line off: works once the job is gone (no browser needed)', !backupMaintenanceActive() && (backupMaintenanceLast()['state'] ?? '') === 'abandoned' && str_ends_with($out, 'EXIT=0'), $out);

    section('Maintenance mode: the restoring administrator stays signed in');
    $token = backupMaintenanceStart($admin, '20261112T000000Z');
    @touch("$sessDir/sess_$adminSid", time() - 3000);
    clearstatcache();
    $http('api/system/backup_rollback_status.php', 'PHPSESSID=' . $adminSid . '; ' . BACKUP_MAINTENANCE_COOKIE . '=' . $token);
    clearstatcache();
    ok('polling the progress keeps the session from being collected', filemtime("$sessDir/sess_$adminSid") > time() - 60, date('c', (int)filemtime("$sessDir/sess_$adminSid")));
    backupMaintenanceEnd(['state' => 'abandoned']);

    // ── A small install of its own: upload folders under a temporary app root, Files in a
    //    temporary folder, a folder target, and the backup settings (all put back at the end).
    section('Set-up');
    $firstRun = (int)$conn->query('SELECT COALESCE(MAX(id), 0) FROM backup_runs')->fetchColumn();
    $cleanup[] = fn() => $conn->prepare('DELETE FROM backup_runs WHERE id > ?')->execute([$firstRun]);
    $snap = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key LIKE 'backup\\_%' OR setting_key LIKE 'files\\_s3\\_%' OR setting_key LIKE 'files\\_storage\\_%'")->fetchAll(PDO::FETCH_KEY_PAIR);
    $cleanup[] = function () use ($conn, $snap) {
        $conn->exec("DELETE FROM system_settings WHERE setting_key LIKE 'backup\\_%' OR setting_key LIKE 'files\\_s3\\_%' OR setting_key LIKE 'files\\_storage\\_%'");
        $ins = $conn->prepare('INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)');
        foreach ($snap as $k => $v) $ins->execute([$k, $v]);
    };
    $conn->exec("DELETE FROM system_settings WHERE setting_key LIKE 'backup\\_%'");
    BackupsService::$kdfOps = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    BackupsService::$kdfMem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    $folder = "$work/target";
    mkdir($folder);
    BackupsService::saveTarget($conn, ['type' => 'folder', 'folder' => $folder], $admin);
    BackupsService::setPassphrase($conn, 'rollback test passphrase', 'rollback test passphrase', $admin);
    BackupsService::saveSchedule($conn, 'off', null, null, 7, $admin);
    $target = backupTargetDriver(backupTargetConfig($conn));
    $installId = backupSetting($conn, 'backup_install_id');

    $app = "$work/app";
    $put = function (string $rel, string $bytes) use ($app) { @mkdir(dirname("$app/$rel"), 0777, true); file_put_contents("$app/$rel", $bytes); };
    $put('uploads/documents/kept.txt', 'original');
    $put('uploads/documents/changed.txt', 'before');
    $put('uploads/documents/.htaccess', 'Require all denied');
    $put('uploads/documents/web.config', '<configuration/>');
    $put('tickets/attachments/1/gone.pdf', 'a pdf');
    $filesDir = "$work/files";
    mkdir($filesDir);
    $files = new LocalDriver($filesDir);
    filesStorageReset();
    FilesStorageCache::$drivers['active'] = $files;
    $conn->prepare("INSERT INTO files_folders (name, created_by, created_datetime) VALUES ('ZZ rollback', ?, UTC_TIMESTAMP())")->execute([$admin]);
    $zzFolder = (int)$conn->lastInsertId();
    $cleanup[] = fn() => $conn->prepare("DELETE FROM files_folders WHERE name LIKE 'ZZ rollback%'")->execute();
    $mkFile = function (string $bytes) use ($conn, $zzFolder, $admin, $files): string {
        $key = gmdate('Y/m/d/') . bin2hex(random_bytes(16)) . '.bin';
        $conn->prepare("INSERT INTO files_items (folder_id, name, size_bytes, mime_type, created_by, created_datetime) VALUES (?, ?, ?, 'text/plain', ?, UTC_TIMESTAMP())")
             ->execute([$zzFolder, 'ZZ ' . bin2hex(random_bytes(3)) . '.txt', strlen($bytes), $admin]);
        $item = (int)$conn->lastInsertId();
        $conn->prepare("INSERT INTO files_versions (item_id, version_no, storage_path, size_bytes, mime_type, sha256, uploaded_by, uploaded_datetime) VALUES (?, 1, ?, ?, 'text/plain', ?, ?, UTC_TIMESTAMP())")
             ->execute([$item, $key, strlen($bytes), hash('sha256', $bytes), $admin]);
        $tmp = tempnam(sys_get_temp_dir(), 'zzf');
        file_put_contents($tmp, $bytes);
        $files->putFile($key, $tmp, true);
        return $key;
    };
    $fKept = $mkFile('files one');
    $fGone = $mkFile('files two');
    $keyPath = "$work/keys/freeitsm.key";
    mkdir(dirname($keyPath));
    copy(ENCRYPTION_KEY_PATH, $keyPath);
    $runner = fn() => new BackupRunner($conn, $target, $app, fn() => null, $keyPath);
    $b1 = $runner()->run('manual', $admin);
    ok('the backup to roll back to is made', $b1['status'] === 'ok', (string)$b1['error']);

    section('The safety backup');
    $pruned = $runner();
    BackupsService::saveSchedule($conn, 'off', null, null, 1, $admin);   // keep 1: a normal run would prune B1
    $s0 = $pruned->run('safety', $admin);
    $kinds = $conn->query('SELECT kind FROM backup_runs ORDER BY id DESC LIMIT 1')->fetchColumn();
    ok('recorded as a safety backup', $s0['status'] === 'ok' && $kinds === 'safety', "$kinds " . $s0['error']);
    ok('it prunes nothing (the set being restored must survive)', $s0['prune'] === null && $target->size("sets/{$b1['set']}/done.json") !== null);
    BackupsService::saveSchedule($conn, 'off', null, null, 7, $admin);
    $seen = 0;
    $counted = $runner();
    $counted->onFile = function () use (&$seen) { $seen++; };
    $counted->run('manual', $admin);
    ok('the runner reports each file (the rollback\'s heartbeat)', $seen === 7, (string)$seen);   // 5 upload files + 2 Files objects

    section('Rolling back');
    // Everything that happens after B1 and must be undone, or kept.
    $conn->prepare("INSERT INTO files_folders (name, created_by, created_datetime) VALUES ('ZZ rollback later row', ?, UTC_TIMESTAMP())")->execute([$admin]);
    $put('uploads/documents/new.txt', 'added after the backup');
    $put('uploads/documents/changed.txt', 'after');
    unlink("$app/tickets/attachments/1/gone.pdf");
    $put('uploads/documents/sub/.htaccess', 'Require all denied');
    $put('uploads/documents/sub/web.config', '<configuration/>');
    $put('uploads/asset-imports/import.csv', 'temporary');
    $fNew = $mkFile('files three');
    $files->delete($fGone);
    $put('../files/_incoming/0123456789abcdef0123456789abcdef.part', 'an upload in progress');
    file_put_contents("$filesDir/notes.txt", 'not a Files key');
    BackupsService::saveSchedule($conn, 'off', null, null, 5, $admin);
    backupSaveSetting($conn, 'files_s3_secret', encryptValue('zz current files secret'));
    $b2 = $runner()->run('manual', $admin);
    $runsBefore = (int)$conn->query('SELECT COUNT(*) FROM backup_runs')->fetchColumn();

    $token = backupMaintenanceStart($admin, $b1['set']);
    $verified = 0;
    $rb = new BackupRollback($conn, $target, $b1['set'], 'rollback test passphrase', $admin, $app, $keyPath, $files, fn() => null);
    $rb->verifySchema = function () use (&$verified) { $verified++; return true; };
    $rb->jobWaitSeconds = 5;
    $res = $rb->run();
    ok('rollback: done', $res['state'] === 'done', json_encode($res));
    ok('rollback: maintenance mode is off, the outcome kept', !backupMaintenanceActive() && (backupMaintenanceLast()['state'] ?? '') === 'done');
    ok('rollback: a row added since is gone', (int)$conn->query("SELECT COUNT(*) FROM files_folders WHERE name = 'ZZ rollback later row'")->fetchColumn() === 0);
    ok('rollback: the schema check ran', $verified === 1);
    ok('upload folders: a file added since is deleted', !is_file("$app/uploads/documents/new.txt"));
    ok('upload folders: a changed file is put back', @file_get_contents("$app/uploads/documents/changed.txt") === 'before');
    ok('upload folders: a deleted file is put back', @file_get_contents("$app/tickets/attachments/1/gone.pdf") === 'a pdf');
    ok('upload folders: an unchanged file is still there', @file_get_contents("$app/uploads/documents/kept.txt") === 'original');
    ok('upload folders: .htaccess and web.config are never deleted', is_file("$app/uploads/documents/sub/.htaccess") && is_file("$app/uploads/documents/sub/web.config")
       && is_file("$app/uploads/documents/.htaccess"));
    ok('upload folders: folders backups skip are left alone', is_file("$app/uploads/asset-imports/import.csv"));
    ok('Files: an object added since is deleted', $files->size($fNew) === null);
    ok('Files: a deleted object is put back', $files->size($fGone) === strlen('files two'));
    ok('Files: an unchanged object is still there', $files->size($fKept) === strlen('files one'));
    ok('Files: anything that is not a Files key is left alone', is_file("$filesDir/notes.txt") && is_file("$filesDir/_incoming/0123456789abcdef0123456789abcdef.part"));
    ok('settings: this install\'s backup settings are kept (not the backup\'s)', BackupsService::keepCount($conn) === 5 && backupSetting($conn, 'backup_install_id') === $installId);
    ok('settings: Files storage settings are kept, still readable', settingGetDecrypted($conn, 'files_s3_secret') === 'zz current files secret');
    $hist = $conn->query('SELECT kind, status, set_name FROM backup_runs ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    $last = end($hist);
    ok('history: kept, plus the safety backup and the restore', count($hist) === $runsBefore + 2 && $last['kind'] === 'restore' && $last['status'] === 'ok'
       && $last['set_name'] === $b1['set'] && $hist[count($hist) - 2]['kind'] === 'safety', json_encode(array_slice($hist, -3)));
    $safety = $hist[count($hist) - 2]['set_name'];
    ok('the safety backup is complete on the target and named in the outcome', $target->size("sets/$safety/done.json") !== null && $res['safety_set'] === $safety);
    ok('a backup made after B1 is still on the target', $target->size("sets/{$b2['set']}/done.json") !== null);
    ok('the encryption key is untouched (it is the same key)', file_get_contents($keyPath) === file_get_contents(ENCRYPTION_KEY_PATH));
    ok('the backup schedule is as it was (not paused)', BackupsService::scheduleMode($conn) === 'off' && backupSetting($conn, 'backup_keep_count') === '5');

    section('A rollback that fails part way is undone');
    $conn->prepare("INSERT INTO files_folders (name, created_by, created_datetime) VALUES ('ZZ rollback row before failure', ?, UTC_TIMESTAMP())")->execute([$admin]);
    $put('uploads/documents/before-failure.txt', 'written before the failed rollback');
    backupMaintenanceStart($admin, $b1['set']);
    $rb = new BackupRollback($conn, $target, $b1['set'], 'rollback test passphrase', $admin, $app, $keyPath, $files, fn() => null);
    $rb->verifySchema = fn() => true;
    $rb->jobWaitSeconds = 5;
    $rb->failAfterDatabase = function () { throw new RuntimeException('ZZ simulated failure'); };
    $res = $rb->run();
    ok('failed: reported, with the reason', $res['state'] === 'failed' && str_contains((string)$res['error'], 'ZZ simulated failure'), json_encode($res));
    ok('failed: the install is as it was (safety backup put back)', (int)$conn->query("SELECT COUNT(*) FROM files_folders WHERE name = 'ZZ rollback row before failure'")->fetchColumn() === 1
       && is_file("$app/uploads/documents/before-failure.txt"));
    ok('failed: maintenance mode is off', !backupMaintenanceActive() && (backupMaintenanceLast()['state'] ?? '') === 'failed');
    $last = $conn->query('SELECT kind, status, error_text FROM backup_runs ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    ok('failed: recorded in the history', $last['kind'] === 'restore' && $last['status'] === 'failed' && str_contains((string)$last['error_text'], 'ZZ simulated failure'), json_encode($last));

    section('A failure before anything changed');
    backupMaintenanceStart($admin, $b1['set']);
    $rb = new BackupRollback($conn, $target, $b1['set'], 'not the passphrase at all', $admin, $app, $keyPath, $files, fn() => null);
    $rb->verifySchema = fn() => true;
    $res = $rb->run();
    ok('a wrong passphrase: failed, no safety backup taken, maintenance off', $res['state'] === 'failed' && $res['safety_set'] === null && !backupMaintenanceActive(), json_encode($res));
    section('When putting the safety backup back fails too');
    backupMaintenanceStart($admin, $b1['set']);
    $mailed = [];
    $rb = new BackupRollback($conn, $target, $b1['set'], 'rollback test passphrase', $admin, $app, $keyPath, $files,
                             function (string $subject, string $body) use (&$mailed) { $mailed[] = $body; });
    $rb->verifySchema = fn() => true;
    $rb->jobWaitSeconds = 5;
    $rb->failAfterDatabase = function () use ($target) {
        $target->delete('sets/' . backupMaintenanceRead()['safety_set'] . '/done.json');   // the safety backup can no longer be opened
        throw new RuntimeException('ZZ simulated failure');
    };
    $res = $rb->run();
    ok('broken: maintenance mode stays on', $res['state'] === 'broken' && backupMaintenanceActive() && (backupMaintenanceRead()['state'] ?? '') === 'broken', json_encode($res));
    ok('broken: the administrators are told the exact command, with --force', isset($mailed[0]) && str_contains($mailed[0], '--set=' . $res['safety_set']) && str_contains($mailed[0], '--force')
       && str_contains($mailed[0], 'scripts/backup_maintenance.php --off'), $mailed[0] ?? '');
    ok('broken: the page says the same', str_contains(t('system.backups.mm_broken'), '--force') && str_contains(t('system.backups.mm_broken'), 'backup_maintenance.php'));
    backupMaintenanceEnd(['state' => 'abandoned']);

    $lock = connectToDatabase();
    $lock->query("SELECT GET_LOCK(" . $lock->quote(JobRun::lockName($conn, 'directory_sync')) . ", 0)");
    backupMaintenanceStart($admin, $b1['set']);
    $rb = new BackupRollback($conn, $target, $b1['set'], 'rollback test passphrase', $admin, $app, $keyPath, $files, fn() => null);
    $rb->verifySchema = fn() => true;
    $rb->jobWaitSeconds = 2;
    $res = $rb->run();
    ok('a background job still running: waits, then gives up without changing anything', $res['state'] === 'failed' && str_contains((string)$res['error'], 'directory_sync')
       && $res['safety_set'] === null && !backupMaintenanceActive(), json_encode($res));
    $lock->query("SELECT RELEASE_LOCK(" . $lock->quote(JobRun::lockName($conn, 'directory_sync')) . ")");

    section('From the page: check, start, follow (over HTTP, the real job)');
    // A backup of this install as it really is (its own upload folders and Files storage).
    filesStorageReset();
    $real = (new BackupRunner($conn, $target, $root, fn() => null))->run('manual', $admin);
    ok('a backup of the real install', $real['status'] === 'ok', (string)$real['error']);
    $realRun = (int)$real['run_id'];
    $conn->prepare("INSERT INTO files_folders (name, created_by, created_datetime) VALUES ('ZZ rollback e2e row', ?, UTC_TIMESTAMP())")->execute([$admin]);
    $csrf = bin2hex(random_bytes(16));
    $sid = $mkSess($admin, $csrf);
    $api = fn(array $body) => $http('api/system/backups.php', 'PHPSESSID=' . $sid, $body, $csrf);
    [$code, $j] = $api(['action' => 'restore_check', 'run_id' => $realRun, 'passphrase' => 'wrong wrong wrong']);
    ok('check: a wrong passphrase says so', $code === 400 && ($j['error'] ?? '') === t('system.backups.err_passphrase_wrong'), json_encode($j));
    [$code, $j] = $api(['action' => 'restore_check', 'run_id' => $realRun, 'passphrase' => 'rollback test passphrase']);
    ok('check: what the backup is, and the key is the same', $code === 200 && ($j['restore']['set'] ?? '') === $real['set'] && ($j['restore']['key_differs'] ?? null) === false
       && ($j['restore']['files'] ?? 0) > 0, json_encode($j));
    ok('check: the date is UTC in the database\'s format (as the page formats dates)', (bool)preg_match('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', (string)($j['restore']['created_at'] ?? '')), (string)($j['restore']['created_at'] ?? ''));
    $restoreRun = (int)$conn->query("SELECT id FROM backup_runs WHERE kind = 'restore' ORDER BY id DESC LIMIT 1")->fetchColumn();
    [$code, $j] = $api(['action' => 'restore_check', 'run_id' => $restoreRun, 'passphrase' => 'rollback test passphrase']);
    ok('check: a restore row is not a backup', $code === 400 && ($j['error'] ?? '') === t('system.backups.err_restore_not_ok'), json_encode($j));
    [$code, $j] = $api(['action' => 'restore_start', 'run_id' => $realRun, 'passphrase' => 'rollback test passphrase', 'confirm' => 'restore']);
    ok('start: refused without RESTORE typed exactly', $code === 400 && ($j['error'] ?? '') === t('system.backups.err_restore_confirm') && !backupMaintenanceActive(), json_encode($j));
    [$code, $j] = $api(['action' => 'restore_start', 'run_id' => $realRun, 'passphrase' => 'not it at all!!', 'confirm' => 'RESTORE']);
    ok('start: refused with a wrong passphrase, nothing switched on', $code === 400 && !backupMaintenanceActive(), json_encode($j));
    backupSaveSetting($conn, 'files_storage_previous', 'ENC:moving');
    [$code, $j] = $api(['action' => 'restore_start', 'run_id' => $realRun, 'passphrase' => 'rollback test passphrase', 'confirm' => 'RESTORE']);
    ok('start: refused while Files is moving storage', $code === 400 && ($j['error'] ?? '') === t('system.backups.err_storage_moving'), json_encode($j));
    backupSaveSetting($conn, 'files_storage_previous', null);

    // Hold a job lock so the restore waits where it can be looked at.
    $lock->query("SELECT GET_LOCK(" . $lock->quote(JobRun::lockName($conn, 'directory_sync')) . ", 0)");
    [$code, $j, , $hdr] = $api(['action' => 'restore_start', 'run_id' => $realRun, 'passphrase' => 'rollback test passphrase', 'confirm' => 'RESTORE']);
    ok('start: accepted, maintenance mode on', $code === 200 && !empty($j['success']) && backupMaintenanceActive(), json_encode($j));
    preg_match('/Set-Cookie: ' . BACKUP_MAINTENANCE_COOKIE . '=([0-9a-f]{64});[^\r\n]*/i', $hdr, $cm);
    ok('start: the browser gets the token cookie (HttpOnly, SameSite=Strict)', isset($cm[1]) && stripos($cm[0], 'httponly') !== false && stripos($cm[0], 'samesite=strict') !== false, trim($hdr));
    $owner = 'PHPSESSID=' . $sid . '; ' . BACKUP_MAINTENANCE_COOKIE . '=' . ($cm[1] ?? '');
    $pid = null;
    for ($i = 0; $i < 30 && !$pid; $i++) { $st = backupMaintenanceRead(); $pid = $st['pid'] ?? null; if (!$pid) sleep(1); }
    $cmdline = $pid ? (string)@file_get_contents("/proc/$pid/cmdline") : '';
    $environ = $pid ? (string)@file_get_contents("/proc/$pid/environ") : '';
    ok('the job runs (its process is known)', (bool)$pid, json_encode(backupMaintenanceRead()));
    if (DIRECTORY_SEPARATOR === '/' && $pid) {
        ok('the passphrase is not on the job\'s command line or in its environment', $cmdline !== '' && !str_contains($cmdline, 'rollback test passphrase')
           && !str_contains($environ, 'rollback test passphrase'), $cmdline);
    }
    sleep(4);
    [$code, $j] = $http('api/system/backup_rollback_status.php', $owner);
    ok('progress: waiting for the background job', $code === 200 && ($j['state'] ?? '') === 'waiting' && str_contains(json_encode($j['log'] ?? []), 'directory_sync'), json_encode($j));
    [$code] = $http('index.php');
    ok('everyone else gets the maintenance page meanwhile', $code === 503, (string)$code);
    $lock->query("SELECT RELEASE_LOCK(" . $lock->quote(JobRun::lockName($conn, 'directory_sync')) . ")");
    $final = null;
    for ($i = 0; $i < 300; $i++) {
        [$code, $j] = $http('api/system/backup_rollback_status.php', $owner);
        if ($code === 200 && empty($j['maintenance'])) { $final = $j; break; }
        sleep(1);
    }
    ok('progress: it finishes, restored', ($final['state'] ?? '') === 'done', json_encode($final ?? $j));
    ok('the row added since the backup is gone', (int)$conn->query("SELECT COUNT(*) FROM files_folders WHERE name = 'ZZ rollback e2e row'")->fetchColumn() === 0);
    [$code, $j] = $http('api/system/backups.php', 'PHPSESSID=' . $sid);
    ok('the page shows the last restore', $code === 200 && ($j['settings']['last_restore']['state'] ?? '') === 'done' && ($j['settings']['last_restore']['set'] ?? '') === $real['set']
       && !str_contains(json_encode($j), 'token_hash'), json_encode($j['settings']['last_restore'] ?? null));
    $last = $conn->query('SELECT kind, status FROM backup_runs ORDER BY id DESC LIMIT 2')->fetchAll(PDO::FETCH_ASSOC);
    ok('the history ends with the safety backup and the restore', ($last[0]['kind'] ?? '') === 'restore' && ($last[0]['status'] ?? '') === 'ok' && ($last[1]['kind'] ?? '') === 'safety', json_encode($last));
    [$code] = $http('index.php');
    ok('pages are back', $code !== 503, (string)$code);
    $out = $cli('cron/backup_rollback.php', '--set=' . $real['set'] . ' --by=' . $admin . ' < /dev/null');
    ok('the job will not run unless a restore is waiting for it', str_contains($out, 'Not started from System') && str_ends_with($out, 'EXIT=2'), $out);

    section('Only the current passphrase starts a restore');
    BackupsService::changePassphrase($conn, 'rollback test passphrase', 'a newer rollback passphrase', 'a newer rollback passphrase', $admin);
    $e = null;
    try { BackupsService::restoreCheck($conn, $realRun, 'rollback test passphrase'); } catch (BackupsInputError $x) { $e = $x->getMessage(); }
    ok('an older passphrase that still opens an older backup is refused (it could not open the safety backup)', $e === 'err_restore_old_passphrase', (string)$e);
    ok('the current passphrase is accepted', BackupsService::restoreCheck($conn, $realRun, 'a newer rollback passphrase')['set'] === $real['set']);
} catch (Throwable $e) {
    ok('no unexpected error', false, get_class($e) . ': ' . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine());
} finally {
    foreach (array_reverse($cleanup) as $c) { try { $c(); } catch (Throwable $ignored) {} }
    $rm = function (string $d) use (&$rm) {
        foreach (glob("$d/{,.}*", GLOB_BRACE) ?: [] as $f) {
            if (in_array(basename($f), ['.', '..'], true)) continue;
            is_dir($f) && !is_link($f) ? $rm($f) : @unlink($f);
        }
        @rmdir($d);
    };
    $rm($work);
}

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
