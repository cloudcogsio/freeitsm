<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * GET /api/v1/tasks/{id}/history (#181) - the task window's History tab over the REST API.
 *
 *   FREEITSM_TEST_DATABASE=<throwaway db> FREEITSM_TEST_URL=http://localhost/<that install> php tests/api-task-history.php
 *
 * A ZZ task with three entries of history - a `created` event by a named analyst, a
 * `due_date_changed` event by the system and an older task_audit "Company" row - is read
 * over real HTTP and compared with TaskHistory::forTask(), the History tab's own reader.
 * A checklist step change (with an exception note) is shown only to a key that also has
 * task_checklists.read, and only while Checklists is switched on - the gate of
 * GET /tasks/{id}/checklists; the setting is put back in finally.
 * Then the refusals: a key without task_history.read (403), a key limited to another
 * company (404, as for a task that does not exist), an id that does not exist (404).
 * A task with no history is an empty list. Adds a ZZ company; everything ZZ is removed in finally.
 * Nothing here writes through a service, so no email or workflow can fire.
 */
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/tenancy.php';
require_once __DIR__ . '/../includes/service_context.php';
require_once __DIR__ . '/../includes/services/task_history.php';

$expected = getenv('FREEITSM_TEST_DATABASE');
$base = rtrim((string)getenv('FREEITSM_TEST_URL'), '/');
if (!$expected || !$base) { echo "(skipped: set FREEITSM_TEST_DATABASE and FREEITSM_TEST_URL)\n"; exit(0); }
$conn = connectToDatabase();
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
if ($conn->query('SELECT DATABASE()')->fetchColumn() !== $expected) { echo "(skipped: config.php does not use $expected)\n"; exit(0); }
if (!TaskHistory::ready($conn)) { echo "(skipped: run Database Verification first - task_events is missing)\n"; exit(0); }

$pass = 0; $fail = 0;
function check(string $what, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  [PASS] $what\n"; }
    else     { $fail++; echo "  [FAIL] $what" . ($detail !== '' ? " - $detail" : '') . "\n"; }
}
/** @return array{0:int,1:array,2:string} status, decoded body, raw body */
$rest = function (string $path, string $key) use ($base): array {
    $ch = curl_init("$base/api/v1/index.php?path=" . rawurlencode($path));
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $key]]);
    $raw = (string)curl_exec($ch);
    return [(int)curl_getinfo($ch, CURLINFO_HTTP_CODE), json_decode($raw, true) ?: ['raw' => substr($raw, 0, 300)], $raw];
};

$tag = 'ZZ181H-' . bin2hex(random_bytes(3));
$keys = []; $tasks = []; $tenants = [];
// Snapshot the module switches; the step checks change them.
$modRow = $conn->query("SELECT setting_value FROM system_settings WHERE setting_key = 'modules_disabled'")->fetchColumn();
$setChecklists = function (bool $on) use ($conn, $modRow): void {
    $list = array_values(array_filter((array)json_decode((string)($modRow ?: '[]'), true), fn($m) => $m !== 'checklists'));
    if (!$on) $list[] = 'checklists';
    $conn->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES ('modules_disabled', ?)
                    ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)")->execute([json_encode($list)]);
};
try {
    $admin = (int)$conn->query("SELECT id FROM analysts WHERE is_active = 1 AND is_admin = 1 ORDER BY id LIMIT 1")->fetchColumn();
    $default = getDefaultTenantId($conn);
    $conn->prepare("INSERT INTO tenants (name) VALUES (?)")->execute(["$tag company"]);
    $other = $tenants[] = (int)$conn->lastInsertId();

    $mk = function (string $title, int $tenant) use ($conn, $admin, &$tasks, $tag): int {
        $conn->prepare("INSERT INTO tasks (title, created_by_id, tenant_id) VALUES (?, ?, ?)")->execute(["$tag $title", $admin, $tenant]);
        return $tasks[] = (int)$conn->lastInsertId();
    };
    $T = $mk('with history', $default);
    $E = $mk('no history', $default);

    // Oldest first, a second apart so the newest-first order is certain.
    $ctx = new ActorContext($admin, null, 'ui', 'en', "$tag analyst");
    TaskHistory::recordStrict($conn, $T, 'created', $ctx, null, '2026-12-01', ['via' => 'manual']);
    $conn->prepare("UPDATE task_events SET created_datetime = UTC_TIMESTAMP() - INTERVAL 3 SECOND WHERE task_id = ?")->execute([$T]);
    $conn->prepare("INSERT INTO task_audit (task_id, analyst_id, field_name, old_value, new_value, source, created_datetime)
                    VALUES (?, ?, 'Company', 'ZZ Old company', 'ZZ New company', 'app', UTC_TIMESTAMP() - INTERVAL 2 SECOND)")
         ->execute([$T, $admin]);
    TaskHistory::recordStrict($conn, $T, 'due_date_changed', null, '2026-12-01', '2026-12-15');
    $conn->prepare("UPDATE task_events SET created_datetime = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE task_id = ? AND event_type = 'due_date_changed'")->execute([$T]);
    // The newest: a checklist step ticked, with a note only checklist readers may see.
    $conn->prepare("INSERT INTO task_checklist_item_events (task_id, task_checklist_id, item_id, checklist_title, item_title, action,
                        before_json, after_json, analyst_id, actor_name, created_datetime)
                    VALUES (?, 0, 0, 'ZZ checklist', 'ZZ step', 'ticked', NULL, ?, ?, ?, UTC_TIMESTAMP())")
         ->execute([$T, json_encode(['result' => 'fail', 'exception_note' => "$tag STEPNOTE"]), $admin, "$tag analyst"]);

    $mkKey = function (array $perms, ?array $companies = null) use ($conn, $admin, &$keys, $tag): string {
        $key = 'fitsm_' . bin2hex(random_bytes(24));
        $conn->prepare('INSERT INTO api_keys (name, key_prefix, key_hash, analyst_id, permissions, company_ids, created_datetime) VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())')
             ->execute(["$tag key", substr($key, 0, 12), hash('sha256', $key), $admin, json_encode($perms), $companies === null ? null : json_encode($companies)]);
        $keys[] = (int)$conn->lastInsertId();
        return $key;
    };
    $reader  = $mkKey(['tasks' => ['read'], 'task_history' => ['read']]);
    $noPerm  = $mkKey(['tasks' => ['read'], 'task_comments' => ['read']]);
    $elsewhere = $mkKey(['tasks' => ['read'], 'task_history' => ['read']], [$other]);
    $checklistReader = $mkKey(['tasks' => ['read'], 'task_history' => ['read'], 'task_checklists' => ['read']]);
    $setChecklists(true);

    echo "GET /tasks/{id}/history with task_history.read\n";
    [$code, $r, $raw] = $rest("/tasks/$T/history", $reader);
    $h = $r['data'] ?? null;
    check('200 with a list', $code === 200 && is_array($h), "$code " . substr($raw, 0, 300));
    check('three entries, newest first', is_array($h) && array_column($h, 'type') === ['due_date_changed', 'Company', 'created'],
        json_encode(array_column((array)$h, 'type')));
    $byType = [];
    foreach ((array)$h as $e) $byType[$e['type']] = $e;
    $c = $byType['created'] ?? [];
    check('created: an event, by the analyst, with the value after',
        ($c['kind'] ?? null) === 'event' && ($c['who'] ?? null) === "$tag analyst" && ($c['actor_kind'] ?? null) === 'analyst'
        && array_key_exists('from', $c) && $c['from'] === null && ($c['to'] ?? null) === '2026-12-01' && ($c['detail']['via'] ?? null) === 'manual', json_encode($c));
    $d = $byType['due_date_changed'] ?? [];
    check('due date change: by the system, with no name, before and after',
        ($d['actor_kind'] ?? null) === 'system' && array_key_exists('who', $d) && $d['who'] === null
        && ($d['from'] ?? null) === '2026-12-01' && ($d['to'] ?? null) === '2026-12-15', json_encode($d));
    $a = $byType['Company'] ?? [];
    check('company move: an audit entry with its source',
        ($a['kind'] ?? null) === 'audit' && ($a['from'] ?? null) === 'ZZ Old company' && ($a['to'] ?? null) === 'ZZ New company'
        && ($a['detail']['source'] ?? null) === 'app', json_encode($a));
    check('times are ISO 8601 with a zone', is_array($h) && $h && !array_filter($h, fn($e) => !preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|[+-]\d\d:\d\d)$/', (string)$e['at'])),
        json_encode(array_column((array)$h, 'at')));
    check('every entry has the same keys', is_array($h) && $h && !array_filter($h, fn($e) =>
        array_keys($e) !== ['at', 'kind', 'type', 'who', 'actor_kind', 'from', 'to', 'detail', 'job_run_id']), json_encode($h));
    check('an empty detail is an object, not a list', str_contains($raw, '"detail":{}'), substr($raw, 0, 600));
    check('no checklist step without task_checklists.read', is_array($h) && !in_array('step', array_column($h, 'kind'), true)
        && !str_contains($raw, 'STEPNOTE'));
    $tab = TaskHistory::forTask($conn, $T, false, false);
    check('the same entries as the History tab (less the steps)', is_array($h) && count($h) === count($tab)
        && array_column($h, 'type') === array_column($tab, 'type') && array_column($h, 'who') === array_column($tab, 'who'));

    echo "Checklist steps\n";
    [$code, $r, $raw] = $rest("/tasks/$T/history", $checklistReader);
    $h = $r['data'] ?? [];
    $st = $h[0] ?? [];
    check('with task_checklists.read: the step, newest, with its result and note',
        $code === 200 && count($h) === 4 && ($st['kind'] ?? null) === 'step' && ($st['type'] ?? null) === 'ticked'
        && ($st['who'] ?? null) === "$tag analyst" && ($st['detail']['step'] ?? null) === 'ZZ step'
        && ($st['detail']['after']['exception_note'] ?? null) === "$tag STEPNOTE", "$code " . substr($raw, 0, 400));
    check('... the same entries as the History tab', array_column($h, 'type') === array_column(TaskHistory::forTask($conn, $T), 'type'));
    $setChecklists(false);
    [$code, $r, $raw] = $rest("/tasks/$T/history", $checklistReader);
    check('with Checklists switched off: no step, the rest still there', $code === 200 && count($r['data'] ?? []) === 3
        && !str_contains($raw, 'STEPNOTE'), "$code " . substr($raw, 0, 300));
    $setChecklists(true);

    echo "A task with no history\n";
    [$code, $r] = $rest("/tasks/$E/history", $reader);
    check('200 and an empty list', $code === 200 && ($r['data'] ?? null) === [], "$code " . json_encode($r));

    echo "Refusals\n";
    [$code, $r] = $rest("/tasks/$T/history", $noPerm);
    check('a key without task_history.read: 403', $code === 403, "$code " . json_encode($r));
    [$code] = $rest("/tasks/$T", $noPerm);
    check('... while the same key reads the task itself (control)', $code === 200, (string)$code);
    [$code, $r] = $rest("/tasks/$T/history", $elsewhere);
    check("a key limited to another company: 404, as if the task did not exist", $code === 404, "$code " . json_encode($r));
    check('... and nothing of the history in the answer', !str_contains(json_encode($r), $tag));
    $T2 = $mk('in the other company', $other);
    [$code] = $rest("/tasks/$T2/history", $elsewhere);
    check("... while it reads a task in its own company (control)", $code === 200, (string)$code);
    $missing = (int)$conn->query("SELECT COALESCE(MAX(id), 0) + 1000 FROM tasks")->fetchColumn();
    [$code] = $rest("/tasks/$missing/history", $reader);
    check('an id that does not exist: 404', $code === 404, (string)$code);
} catch (Throwable $e) {
    check('no exception', false, get_class($e) . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
} finally {
    if ($modRow === false) $conn->exec("DELETE FROM system_settings WHERE setting_key = 'modules_disabled'");
    else $conn->prepare("UPDATE system_settings SET setting_value = ? WHERE setting_key = 'modules_disabled'")->execute([$modRow]);
    if ($keys) $conn->exec("DELETE FROM api_keys WHERE id IN (" . implode(',', $keys) . ")");
    if ($tasks) {
        $in = implode(',', $tasks);
        $conn->exec("DELETE FROM task_events WHERE task_id IN ($in)");
        $conn->exec("DELETE FROM task_audit WHERE task_id IN ($in)");
        $conn->exec("DELETE FROM task_checklist_item_events WHERE task_id IN ($in)");
        $conn->exec("DELETE FROM tasks WHERE id IN ($in)");
    }
    if ($tenants) $conn->exec("DELETE FROM tenants WHERE id IN (" . implode(',', $tenants) . ")");
}
echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
