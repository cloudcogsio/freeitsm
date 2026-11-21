<?php
/**
 * Telling the people concerned about backups (#286, wiki Storage-Series-Follow-Ups N2).
 *
 * A changed target sends a copy of everything somewhere else; a changed passphrase or
 * schedule decides whether there is a usable backup at all; a failed backup or Verify means
 * there may not be one. Each is told with a bell and, when a mailbox can send, an email - the
 * pattern of the API threat protection alerts (apiSecurityNotifyAdmins()).
 *
 * Who: every active administrator, and every active analyst who holds Storage and backups
 * (Cap::FILES_STORAGE_BACKUPS) and can open Files - the people who can open System -> Backups.
 * Never the person who did it. A successful backup tells nobody: a bell every night is noise.
 *
 * Never throws: telling people must never break the change itself, or a backup.
 */

require_once __DIR__ . '/../functions.php';

final class BackupNotify
{
    /**
     * Tests replace the email sender so a test never emails anyone (as MandatoryFields::$mailer):
     * fn(string $to, string $subject, string $html): void. Null: mail goes out as normal.
     */
    public static $mailer = null;

    /** The notification types (NotificationsService::types()), by event. */
    public const TYPES = ['changed' => 'backup.changed', 'failed' => 'backup.failed'];
}

/**
 * The analysts told about backups: active administrators, and active holders of Storage and
 * backups who can open Files.
 *
 * @return array<int, array{id: int, email: string}>
 */
function backupNotifyRecipients(PDO $conn): array
{
    require_once __DIR__ . '/../rbac.php';
    $out = [];
    foreach ($conn->query("SELECT id, email FROM analysts WHERE is_admin = 1 AND is_active = 1")->fetchAll(PDO::FETCH_ASSOC) as $a) {
        $out[(int)$a['id']] = ['id' => (int)$a['id'], 'email' => (string)$a['email']];
    }
    // Holders through a role of their own or of an active team; then asked the one way
    // every guard asks (a retired key, an inactive role or a module they cannot open: not told).
    $s = $conn->prepare(
        "SELECT DISTINCT a.id, a.email
           FROM analysts a
          WHERE a.is_active = 1 AND a.is_admin = 0 AND a.id IN (
                SELECT ar.analyst_id FROM rbac_analyst_roles ar
                  JOIN rbac_role_capabilities rc ON rc.role_id = ar.role_id
                 WHERE rc.capability_key = ?
                UNION
                SELECT at.analyst_id FROM analyst_teams at
                  JOIN rbac_team_roles tr ON tr.team_id = at.team_id
                  JOIN rbac_role_capabilities rc ON rc.role_id = tr.role_id
                 WHERE rc.capability_key = ?)");
    $key = capKey(Cap::FILES_STORAGE_BACKUPS);
    try {
        $s->execute([$key, $key]);
        $holders = $s->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $holders = [];   // no roles tables yet: administrators only
    }
    foreach ($holders as $a) {
        $id = (int)$a['id'];
        if (analystHasCapability($conn, $id, Cap::FILES_STORAGE_BACKUPS) && analystCanAccessModule($conn, $id, 'files')) {
            $out[$id] = ['id' => $id, 'email' => (string)$a['email']];
        }
    }
    return array_values($out);
}

/**
 * A bell and an email to everyone concerned (backupNotifyRecipients()) but the actor.
 *
 * @param string $event    'changed' (target, passphrase, schedule) or 'failed' (a backup or a Verify)
 * @param string $title    one line, e.g. 'Backup target changed'
 * @param string $message  what happened - never a secret
 * @param ?int   $actorId  who did it (not told); null = nobody (a scheduled backup) - never 0
 * @param int    $entityId what the bell row is about: a run id, or 1 for the settings (rows about one
 *                         thing coalesce while unread)
 */
function backupNotify(PDO $conn, string $event, string $title, string $message, ?int $actorId = null, int $entityId = 1): void
{
    $type = BackupNotify::TYPES[$event] ?? null;
    if ($type === null) throw new InvalidArgumentException("Unknown backup notification: $event");
    try {
        $people = array_values(array_filter(backupNotifyRecipients($conn), fn($a) => $a['id'] !== $actorId));
    } catch (Throwable $e) {
        error_log('[backups] could not list who to tell: ' . $e->getMessage());
        return;
    }
    if (!$people) return;
    try {
        require_once __DIR__ . '/../services/notifications.php';
        foreach ($people as $a) {
            NotificationsService::notify($conn, [
                'analyst_id' => $a['id'], 'event_type' => $type, 'entity_type' => 'backup', 'entity_id' => max(1, $entityId),
                'title' => mb_substr($title, 0, 255), 'body' => mb_substr($message, 0, 500),
                'actor_id' => $actorId, 'actor_name' => null,
            ]);
        }
    } catch (Throwable $e) {
        error_log('[backups] bell: ' . $e->getMessage());
    }
    try {
        require_once __DIR__ . '/../self_service_email.php';
        $html = '<p>' . nl2br(htmlspecialchars($message)) . '</p><p>' . htmlspecialchars(backupT('n_email_footer')) . '</p>';
        foreach ($people as $a) {
            if (!filter_var($a['email'], FILTER_VALIDATE_EMAIL)) continue;
            if (!NotificationsService::typeEnabled($conn, $a['id'], $type)) continue;   // each person's own switch, as for the bell
            if (BackupNotify::$mailer) { (BackupNotify::$mailer)($a['email'], 'FreeITSM: ' . $title, $html); continue; }
            ssSendSystemEmail($conn, $a['email'], 'FreeITSM: ' . $title, $html, 'backup');   // no mailbox: logged in the send log
        }
    } catch (Throwable $e) {
        error_log('[backups] email: ' . $e->getMessage());
    }
}

/** A backup target as people read it - never its secret. */
function backupTargetLabel(?array $cfg): string
{
    if ($cfg === null) return backupT('label_target_none');
    if ($cfg['type'] === 'folder') return backupT('label_target_folder', ['folder' => $cfg['folder']]);
    return backupT('label_target_s3', ['bucket' => $cfg['bucket'] . ($cfg['prefix'] !== '' ? '/' . rtrim($cfg['prefix'], '/') : ''), 'endpoint' => $cfg['endpoint']]);
}

/** A backups string (lang/<locale>/system.php, backups.*): messages, alerts and progress lines. */
function backupT(string $key, array $params = []): string
{
    require_once __DIR__ . '/../i18n.php';
    return I18n::t('system.backups.' . $key, $params);
}
