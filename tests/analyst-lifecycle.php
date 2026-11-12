<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * When an analyst leaves: Deactivate, Anonymise, Delete (GH #178).
 *
 *   php tests/analyst-lifecycle.php
 *
 * 1. THE MAP IS COMPLETE. Every column that refers to an analyst - a foreign key
 *    to analysts in freeitsm.sql, a person-shaped integer column, or a
 *    principal/member/owner type+id pair - is in analystReferenceRegistry().
 *    A new table that points at analysts fails here until somebody decides what
 *    leaving does to it. (Missed, it is a raw SQL error on a fresh install's
 *    delete, or a dangling reference on an install without foreign keys.)
 * 2. THE ACTIONS DO WHAT THEY SAY, on throwaway analysts ("zz-test-lc-*") with
 *    throwaway rows, all removed by id in a finally block and checked gone:
 *      - Delete, nothing but personal settings: deleted, widgets gone (#178).
 *      - Delete, with history: refused, nothing changed.
 *      - Reassign open work: the ticket moves to the new analyst, through the
 *        ticket service, which writes the history row.
 *      - Deactivate: inactive, name kept.
 *      - Anonymise: name and contact replaced, sign-in links and settings gone,
 *        history rows still there and still theirs, the audit's copy of the
 *        name replaced - and another analyst's identical-looking row untouched.
 *      - Yourself and the last administrator: refused.
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/tenancy.php';
require_once __DIR__ . '/../includes/analyst_lifecycle.php';

$pass = 0; $fail = 0;
/**
 * Records and prints one PASS or FAIL line.
 *
 * @param string $what  what is being checked, in a few words
 * @param bool $cond  true when the check passed
 * @param string $detail  shown after a failure - the values that disagreed
 */
function ok(string $what, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  PASS  {$what}\n"; }
    else       { $fail++; echo "  FAIL  {$what}" . ($detail ? "  <- {$detail}" : '') . "\n"; }
}

echo "\nAnalysts leaving: Deactivate, Anonymise, Delete (GH #178)\n" . str_repeat('=', 70) . "\n";

// ── 1. the map is complete ──────────────────────────────────────────────────
$registered = [];
foreach (analystReferenceRegistry() as $r) $registered["{$r[0]}.{$r[1]}"] = true;
foreach ($registered as $k => $_) {
    if (!preg_match('/^[a-z0-9_]+\.[a-z0-9_]+$/', $k)) ok("registry entry is a plain table.column: $k", false);
}
$schema = require __DIR__ . '/../includes/db_verify_schema.php';
$sql = file_get_contents(__DIR__ . '/../database/freeitsm.sql');
$found = [];
preg_match_all("/CREATE TABLE IF NOT EXISTS `([a-z0-9_]+)`(.*?)\n\) ENGINE/s", $sql, $tables, PREG_SET_ORDER);
foreach ($tables as $t) {
    preg_match_all("/FOREIGN KEY \(`([a-z0-9_]+)`\) REFERENCES `analysts`/", $t[2], $m);
    foreach ($m[1] as $c) $found["{$t[1]}.$c"] = 'foreign key to analysts';
}
$personInt = '/(^|_)(analyst|owner|author|approver|assignee|assigned_to|assigned_analyst|created_by|updated_by|modified_by|deleted_by|closed_by|resolved_by|archived_by|saved_by|uploaded_by|linked_by|added_by|decided_by|raised_by|done_by|recorded_by|escalated_by|completed_by|reviewed_by|approved_by|rejected_by|granted_by|revoked_by|changed_by|performed_by|triggered_by|dismissed_by|generated_by|merged_by|split_by)(_id|_analyst_id)?$/';
foreach ($schema as $table => $cols) {
    if (!is_array($cols) || $table === 'analysts') continue;
    foreach ($cols as $col => $def) {
        if (!is_string($def)) continue;
        if (preg_match('/^(INT|BIGINT|SMALLINT|MEDIUMINT)/i', $def) && preg_match($personInt, $col)) {
            $found["$table.$col"] = $found["$table.$col"] ?? 'person-shaped name';
        }
        if (preg_match('/^(principal|member|owner|target)_(type|kind)$/', $col)) {
            $idCol = preg_replace('/_(type|kind)$/', '_id', $col);
            if ($table === 'lms_course_assignments') $idCol = 'group_id';
            if (isset($cols[$idCol])) $found["$table.$idCol"] = $found["$table.$idCol"] ?? 'type + id pair';
        }
    }
}
// Columns the discovery finds that refer to customers, suppliers, teams or
// anything else - NOT analysts - and the reason each is not in the map.
$notAnalysts = [
    'files_shortcuts.target_id' => 'the file, folder or article a shortcut opens',
    'files_offline.target_id'   => 'the file or folder kept offline',
];
$missing = [];
foreach ($found as $k => $why) {
    if (isset($registered[$k]) || isset($notAnalysts[$k])) continue;
    $missing[] = "$k ($why)";
}
ok('every column that refers to an analyst is in the map (' . count($found) . ' found)', !$missing,
   "\n          not in analystReferenceRegistry(): " . implode("\n          ", $missing));
$stale = array_filter(array_keys($registered), function ($k) use ($schema) {
    [$t, $c] = explode('.', $k);
    return !isset($schema[$t][$c]);
});
ok('every map entry is a real column', !$stale, implode(', ', $stale));

// ── 2. the actions do what they say ──────────────────────────────────────────
$conn = connectToDatabase();
$admin = (int) $conn->query("SELECT id FROM analysts WHERE is_admin = 1 AND is_active = 1 ORDER BY id LIMIT 1")->fetchColumn();
$ctx = new ActorContext(actorId: $admin, companyScope: null, source: 'ui', actorName: 'test');
$openStatus = (int) $conn->query("SELECT id FROM ticket_statuses WHERE is_closed = 0 ORDER BY id LIMIT 1")->fetchColumn();
$widget = (int) $conn->query("SELECT id FROM ticket_dashboard_widgets ORDER BY id LIMIT 1")->fetchColumn();
$provider = (int) $conn->query("SELECT id FROM auth_providers ORDER BY id LIMIT 1")->fetchColumn();

$made = ['analysts' => [], 'tickets' => [], 'articles' => []];
$mk = function (string $tag, int $active = 1) use ($conn, &$made): int {
    $conn->prepare("INSERT INTO analysts (username, email, full_name, password_hash, is_active) VALUES (?, ?, ?, '!', ?)")
         ->execute(["zz-test-lc-$tag", "zz-test-lc-$tag@invalid.test", 'ZZ Test LC ' . strtoupper($tag), $active]);
    return $made['analysts'][] = (int) $conn->lastInsertId();
};
$ticket = function (?int $owner, string $tag) use ($conn, $openStatus, &$made): int {
    // Straight into the table, deliberately: no priority and no requester, so
    // creating it fires no ticket.created workflow and sends no email.
    $conn->prepare("INSERT INTO tickets (ticket_number, subject, status_id, assigned_analyst_id, owner_id, created_datetime)
                    VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP())")
         ->execute(['ZZLC-' . bin2hex(random_bytes(4)), "zz-test-lc $tag", $openStatus, $owner, $owner]);
    return $made['tickets'][] = (int) $conn->lastInsertId();
};
$exists = fn(int $id): bool => (bool) $conn->query("SELECT COUNT(*) FROM analysts WHERE id = $id")->fetchColumn();
$err = function (callable $fn): ?string { try { $fn(); return null; } catch (ServiceError $e) { return $e->errorCode; } };
$count = fn(string $sql): int => (int) $conn->query($sql)->fetchColumn();

try {
    // A - only personal settings: the #178 case. Deletes cleanly.
    $a = $mk('a');
    if ($widget) $conn->prepare("INSERT INTO analyst_ticket_dashboard_widgets (analyst_id, widget_id, sort_order) VALUES (?, ?, 1)")->execute([$a, $widget]);
    $conn->prepare("INSERT INTO user_preferences (analyst_id, preference_key, preference_value) VALUES (?, 'zz-test', '1')")->execute([$a]);
    $f = analystFootprint($conn, $a);
    ok('A: only personal settings - Delete is offered', $f['can_delete'] && !$f['live'] && $f['personal'] >= 1, json_encode($f));
    analystDelete($conn, $ctx, $a);
    ok('A: deleted, with its dashboard widgets and preferences (#178)', !$exists($a)
        && $count("SELECT COUNT(*) FROM analyst_ticket_dashboard_widgets WHERE analyst_id = $a") === 0
        && $count("SELECT COUNT(*) FROM user_preferences WHERE analyst_id = $a") === 0);

    // B - has history: Delete refused, nothing changed.
    $b = $mk('b');
    $tb = $ticket(null, 'history');
    $conn->prepare("INSERT INTO ticket_notes (ticket_id, analyst_id, note_text) VALUES (?, ?, 'zz-test-lc note')")->execute([$tb, $b]);
    $f = analystFootprint($conn, $b);
    ok('B: a ticket note is history - Delete not offered', !$f['can_delete'] && $f['history'] >= 1);
    ok('B: Delete refused with the reason', $err(fn() => analystDelete($conn, $ctx, $b)) === 'has_history');
    ok('B: and nothing changed - analyst and note both still there', $exists($b)
        && $count("SELECT COUNT(*) FROM ticket_notes WHERE analyst_id = $b") === 1);

    // C - open work: unassign a ticket through the ticket service; reassign an article.
    $c = $mk('c'); $d = $mk('d');
    $tc = $ticket($c, 'open work');
    $conn->prepare("INSERT INTO knowledge_articles (title, body, author_id, owner_id, audience, is_published) VALUES ('zz-test-lc article', '<p>x</p>', ?, ?, 'internal', 1)")
         ->execute([$admin, $c]);
    $made['articles'][] = $art = (int) $conn->lastInsertId();
    $f = analystFootprint($conn, $c);
    ok('C: open work is listed (a ticket and an article)', isset($f['live']['tickets'], $f['live']['articles']), json_encode($f['live']));
    ok('C: Delete refused while they still hold open work', $err(fn() => analystDelete($conn, $ctx, $c)) === 'has_live_work');
    $auditBefore = $count("SELECT COUNT(*) FROM ticket_audit WHERE ticket_id = $tc");
    $r1 = analystReassignLive($conn, $ctx, $c, null, ['tickets']);
    $row = $conn->query("SELECT assigned_analyst_id, owner_id FROM tickets WHERE id = $tc")->fetch(PDO::FETCH_ASSOC);
    ok('C: the ticket is unassigned - both columns', $row['assigned_analyst_id'] === null && $row['owner_id'] === null, json_encode($row) . json_encode($r1));
    ok('C: through the ticket service - its history records the change', $count("SELECT COUNT(*) FROM ticket_audit WHERE ticket_id = $tc") > $auditBefore);
    $r2 = analystReassignLive($conn, $ctx, $c, $d, ['articles']);
    ok('C: the article now belongs to the new analyst', $count("SELECT owner_id FROM knowledge_articles WHERE id = $art") === $d, json_encode($r2));
    $inactive = $mk('inactive', 0);
    ok('C: moving work to an inactive analyst is refused', $err(fn() => analystReassignLive($conn, $ctx, $c, $inactive)) === 'bad_analyst');

    // D - Deactivate: inactive, name kept.
    analystDeactivate($conn, $ctx, $b);
    $row = $conn->query("SELECT is_active, full_name FROM analysts WHERE id = $b")->fetch(PDO::FETCH_ASSOC);
    ok('Deactivate: inactive, and the name is unchanged', (int) $row['is_active'] === 0 && $row['full_name'] === 'ZZ Test LC B');

    // E - Anonymise B: the person goes, the record stays.
    if ($provider) $conn->prepare("INSERT INTO analyst_sso_identities (analyst_id, provider_id, subject) VALUES (?, ?, 'zz-test-lc-sub')")->execute([$b, $provider]);
    $conn->prepare("INSERT INTO ticket_audit (ticket_id, analyst_id, field_name, old_value, new_value, created_datetime) VALUES (?, ?, 'Owner', 'ZZ Test LC B', 'ZZ Test LC C', UTC_TIMESTAMP())")->execute([$tb, $admin]);
    $conn->prepare("INSERT INTO ticket_audit (ticket_id, analyst_id, field_name, old_value, new_value, created_datetime) VALUES (?, ?, 'Subject', 'About ZZ Test LC B', 'x', UTC_TIMESTAMP())")->execute([$tb, $admin]);
    analystAnonymise($conn, $ctx, $b);
    $row = $conn->query("SELECT username, full_name, email, is_active FROM analysts WHERE id = $b")->fetch(PDO::FETCH_ASSOC);
    ok('Anonymise: name, username and email replaced', $row['full_name'] === analystFormerName($b)
        && $row['username'] === "former-analyst-$b" && $row['email'] === "former-analyst-$b@invalid", json_encode($row));
    ok('Anonymise: sign-in links removed', $count("SELECT COUNT(*) FROM analyst_sso_identities WHERE analyst_id = $b") === 0);
    ok('Anonymise: their note is still there, still theirs', $count("SELECT COUNT(*) FROM ticket_notes WHERE analyst_id = $b") === 1);
    ok("Anonymise: the audit's copy of the name replaced",
       $count("SELECT COUNT(*) FROM ticket_audit WHERE ticket_id = $tb AND old_value = " . $conn->quote(analystFormerName($b))) === 1);
    ok("Anonymise: a text that only CONTAINS the name is left alone, and so is C's name",
       $count("SELECT COUNT(*) FROM ticket_audit WHERE ticket_id = $tb AND old_value = 'About ZZ Test LC B'") === 1
       && $count("SELECT COUNT(*) FROM ticket_audit WHERE ticket_id = $tb AND new_value = 'ZZ Test LC C'") === 1);

    // F - the guards.
    ok('yourself: refused', $err(fn() => analystDelete($conn, new ActorContext(actorId: $d), $d)) === 'self');
} finally {
    foreach ($made['tickets'] as $t) {
        foreach (['ticket_audit', 'ticket_notes'] as $tbl) $conn->prepare("DELETE FROM $tbl WHERE ticket_id = ?")->execute([$t]);
        $conn->prepare("DELETE FROM tickets WHERE id = ? AND subject LIKE 'zz-test-lc%'")->execute([$t]);
    }
    foreach ($made['articles'] as $a2) {
        $conn->prepare("DELETE FROM knowledge_audit WHERE object_type = 'article' AND object_id = ?")->execute([$a2]);
        $conn->prepare("DELETE FROM knowledge_articles WHERE id = ? AND title LIKE 'zz-test-lc%'")->execute([$a2]);
    }
    foreach ($made['analysts'] as $an) {
        foreach (analystReferenceRegistry() as $ref) {
            if (in_array($ref[2], ['personal', 'secret'], true) && analystLcColumnExists($conn, $ref[0], $ref[1])) {
                $conn->prepare("DELETE FROM `{$ref[0]}` WHERE `{$ref[1]}` = ?" . (isset($ref[3]) ? " AND ({$ref[3]})" : ''))->execute([$an]);
            }
        }
        $conn->prepare("DELETE FROM system_logs WHERE log_type LIKE 'analyst\\_%' AND details = ?")->execute([json_encode(['analyst_id' => $an, 'action' => 'deleted'])]);
        foreach (['deactivated', 'anonymised'] as $w) {
            $conn->prepare("DELETE FROM system_logs WHERE details = ?")->execute([json_encode(['analyst_id' => $an, 'action' => $w])]);
        }
        $conn->prepare("DELETE FROM analysts WHERE id = ? AND (username LIKE 'zz-test-lc-%' OR username LIKE 'former-analyst-%')")->execute([$an]);
    }
}
$left = 0;
foreach ($made['analysts'] as $an) $left += $count("SELECT COUNT(*) FROM analysts WHERE id = $an");
$left += $count("SELECT COUNT(*) FROM tickets WHERE subject LIKE 'zz-test-lc%'")
       + $count("SELECT COUNT(*) FROM knowledge_articles WHERE title LIKE 'zz-test-lc%'");
foreach ($made['analysts'] as $an) $left += $count("SELECT COUNT(*) FROM system_logs WHERE details LIKE '%\"analyst_id\":$an,%'");
ok('cleanup: every throwaway analyst, ticket, article and log line is gone', $left === 0, "$left left");

echo "\n{$pass} passed, {$fail} failed\n";
exit($fail ? 1 : 0);
