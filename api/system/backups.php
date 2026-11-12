<?php
/**
 * API: System -> Backups (#286). Administrators only.
 *
 * GET  - the settings (no secrets) and the latest runs
 * POST - {action: test | save_target | set_passphrase | change_passphrase | save_schedule | backup_now | verify, ...}
 *
 * Errors come back as translated text; never exception or database detail, except the
 * storage error a Test connection shows (as the Files Storage tab does).
 */
session_start(['read_and_close' => true]);
require_once '../../config.php';
require_once '../../includes/admin_api_guard.php';   // signed in AND an administrator
require_once '../../includes/functions.php';
require_once '../../includes/i18n.php';
require_once '../../includes/services/backups.php';

header('Content-Type: application/json');
I18n::initFromSession();

$conn = connectToDatabase();
$analystId = (int)$_SESSION['analyst_id'];

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo json_encode(['success' => true, 'settings' => BackupsService::describe($conn), 'runs' => BackupsService::runs($conn)]);
    exit;
}

csrfRequireWriteMethod();
$in = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($in)) $in = [];
$action = (string)($in['action'] ?? '');

try {
    switch ($action) {
        case 'test':
            echo json_encode(['success' => true, 'test' => BackupsService::test((array)($in['target'] ?? []), $conn)]);
            break;
        case 'save_target':
            BackupsService::saveTarget($conn, (array)($in['target'] ?? []), $analystId);
            echo json_encode(['success' => true]);
            break;
        case 'set_passphrase':
            BackupsService::setPassphrase($conn, (string)($in['passphrase'] ?? ''), (string)($in['confirm'] ?? ''), $analystId);
            echo json_encode(['success' => true]);
            break;
        case 'change_passphrase':
            BackupsService::changePassphrase($conn, (string)($in['current'] ?? ''), (string)($in['passphrase'] ?? ''), (string)($in['confirm'] ?? ''), $analystId);
            echo json_encode(['success' => true]);
            break;
        case 'save_schedule':
            BackupsService::saveSchedule($conn, (string)($in['mode'] ?? ''), isset($in['weekday']) && $in['weekday'] !== '' ? (int)$in['weekday'] : null,
                                         isset($in['time']) && $in['time'] !== '' ? (string)$in['time'] : null, (int)($in['keep'] ?? 0), $analystId);
            echo json_encode(['success' => true]);
            break;
        case 'backup_now':
            BackupsService::backupNow($conn, $analystId);
            echo json_encode(['success' => true]);
            break;
        case 'verify':
            // Decrypting a large backup takes a while: carry on if the browser gives up;
            // the result is recorded on the run either way.
            ignore_user_abort(true);
            set_time_limit(0);
            $r = BackupsService::verify($conn, (int)($in['run_id'] ?? 0), (string)($in['passphrase'] ?? ''), $analystId);
            echo json_encode(['success' => true, 'verify' => ['ok' => $r['ok'], 'checked' => $r['checked'], 'errors' => array_slice($r['errors'], 0, 20)]]);
            break;
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => t('system.backups.err_action')]);
    }
} catch (BackupsInputError $e) {
    http_response_code($e->getMessage() === 'err_running' ? 409 : 400);
    echo json_encode(['success' => false, 'error' => t('system.backups.' . $e->getMessage())]);
} catch (Throwable $e) {
    error_log('[backups] ' . $action . ': ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => t('system.backups.err_server')]);
}
