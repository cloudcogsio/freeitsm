<?php
/**
 * Who may open a System page - the one rule, used by page_gate.php and header.php (GH #263).
 */
require_once __DIR__ . '/../../includes/functions.php';

/**
 * May this analyst open this System page?
 *
 * An administrator may open any; every analyst may open Preferences, their own.
 * A page that moved here from a module keeps the people who could use it there
 * (GH #263): it sets $system_page_grant = ['module' => 'assets', 'cap' => Cap::ASSETS_INTUNE]
 * before requiring this file, and an analyst with that module and capability may
 * open it too. Its endpoints check the same capability, as they always did.
 *
 * @param ?array $grant  ['module' => string, 'cap' => Cap or its key, capKey(Cap::X)] or null - the
 *                       page's own exception. The key is the form capabilities.php asks data to hold.
 */
function systemPageAllowed(PDO $conn, int $analystId, string $page, ?array $grant): bool
{
    if ($page === 'preferences') return true;
    if (analystIsAdmin($conn, $analystId)) return true;
    if ($grant === null || empty($grant['module']) || !isset($grant['cap'])) return false;
    require_once __DIR__ . '/../../includes/rbac.php';
    try {
        $key = $grant['cap'] instanceof Cap ? capKey($grant['cap']) : (string)$grant['cap'];
        return analystCanAccessModule($conn, $analystId, (string)$grant['module'])
            && analystHasCapability($conn, $analystId, Cap::from($key));   // an unknown key throws: refused below
    } catch (Throwable $e) {
        return false;   // fail closed
    }
}
