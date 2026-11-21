<?php
/**
 * API: War room — serve an attachment.
 *
 * GET ?id=<int>
 *
 * 🔒 TWO RULES, AND NEITHER IS OPTIONAL.
 *
 * 1. AUTHORISATION IS THE CHANNEL'S. warRoomAttachmentFor() resolves the file
 *    through its message to its channel and applies exactly the same access rule
 *    as reading the conversation. Guessing an attachment id from a DM you are not
 *    in returns 404, not the file. The check is in the service layer rather than
 *    here so there is one answer to "may I read this", shared with every other
 *    caller.
 *
 * 2. THE CONTENT TYPE IS OURS, NOT THE UPLOADER'S. attachmentSendHeaders() works
 *    it out from the file extension against ATTACHMENT_SERVE_TYPES and adds
 *    nosniff (security finding F5). This is why there is no content_type column
 *    to consult: an attachment that could declare itself image/svg+xml could run
 *    script in the reader's session, because SVG is XML and the browser opens it
 *    as a top-level document on our own origin.
 *
 * The bytes live outside any directory the web server will execute from — see
 * includes/uploads.php — but that is the net under the tightrope, not the
 * tightrope. Nothing is ever fetched from that folder directly.
 */
session_start(['read_and_close' => true]);
require_once '../../config.php';
require_once '../../includes/functions.php';
require_once '../../includes/warroom.php';

requireModuleAccessJson('war-room');

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

try {
    $conn = connectToDatabase();
    $row  = warRoomAttachmentFor($conn, (int) $_SESSION['analyst_id'], $id);
} catch (Throwable $e) {
    $row = null;
}

// One response for "no such file", "not yours" and "gone from disk". Telling the
// three apart would let somebody map which attachment ids exist in channels they
// cannot read.
if ($row === null || !is_file($row['path'])) {
    http_response_code(404);
    header('Content-Type: text/plain');
    echo 'Not found';
    exit;
}

attachmentSendHeaders((string) $row['original_name'], (int) filesize($row['path']));
readfile($row['path']);
