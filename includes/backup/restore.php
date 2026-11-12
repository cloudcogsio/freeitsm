<?php
/**
 * Reading backups back (#286): listing the sets on a target, opening one with the
 * passphrase, verifying it, and restoring it (BackupRestore, used by
 * scripts/backup_restore.php).
 */

require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/dump.php';
require_once __DIR__ . '/target.php';

/**
 * The sets on a target, newest first.
 *
 * @return array<int, array{name: string, complete: bool, install_id: ?string, size: ?int, files: ?int, created_at: ?string}>
 */
function backupListSets(StorageDriver&StorageLister $t): array
{
    $sets = [];
    foreach ($t->listKeys('sets/') as $k) {
        $parts = explode('/', $k, 3);
        if (count($parts) === 3) $sets[$parts[1]][$parts[2]] = true;
    }
    krsort($sets, SORT_STRING);
    $out = [];
    foreach ($sets as $name => $objs) {
        $done = isset($objs['done.json']) ? backupReadJson($t, "sets/$name/done.json") : null;
        $out[] = [
            'name'       => (string)$name,
            'complete'   => is_array($done),
            'install_id' => is_array($done) ? (string)($done['install_id'] ?? '') : null,
            'size'       => is_array($done) ? (int)($done['size'] ?? 0) : null,
            'files'      => is_array($done) ? (int)($done['files'] ?? 0) : null,
            'created_at' => is_array($done) ? (string)($done['created_at'] ?? '') : null,
        ];
    }
    return $out;
}

/**
 * Opens a complete set with the passphrase.
 *
 * @return array{keys: array, datakey: string, manifest: array}
 * @throws BackupWrongPassphrase|BackupCorrupt|StorageUnavailable|RuntimeException
 */
function backupOpenSet(StorageDriver&StorageLister $t, string $set, string $passphrase): array
{
    if (!preg_match('/^\d{8}T\d{6}Z$/', $set)) throw new InvalidArgumentException('That is not a backup name.');
    if ($t->size("sets/$set/done.json") === null) throw new RuntimeException("Backup $set is not complete (or does not exist).");
    $keyring = null;
    try {
        $keyring = backupReadJson($t, 'keyring.json');
    } catch (StorageNotFound $e) {
        // fall back to the set's own copy below
    }
    $keyring ??= backupReadJson($t, "sets/$set/keyring.json");
    if (!is_array($keyring)) throw new BackupCorrupt('The backup keyring could not be read.');
    $keys = backupUnlockKeyring($keyring, $passphrase);
    try {
        $dataKey = backupOpenKey(backupReadString($t, "sets/$set/datakey.bin"), $keys['public'], $keys['secret']);
    } catch (BackupCorrupt $e) {
        // The target keyring may be a newer keypair's (a target reused after a fresh start):
        // the set's own copy is the one it was made with.
        $own = backupReadJson($t, "sets/$set/keyring.json");
        if (!is_array($own)) throw $e;
        $keys = backupUnlockKeyring($own, $passphrase);
        $dataKey = backupOpenKey(backupReadString($t, "sets/$set/datakey.bin"), $keys['public'], $keys['secret']);
    }
    $manifest = json_decode(backupDecryptString(backupReadString($t, "sets/$set/manifest.bin"), $dataKey), true);
    if (!is_array($manifest) || (int)($manifest['format'] ?? 0) !== 1) throw new BackupCorrupt('The backup manifest is not readable.');
    return ['keys' => $keys, 'datakey' => $dataKey, 'manifest' => $manifest];
}

/** The whole object as a string (small objects only). */
function backupReadString(StorageDriver $t, string $key): string
{
    $p = sys_get_temp_dir() . '/bkread-' . bin2hex(random_bytes(6));
    try {
        $t->readTo($key, $p);
        $s = @file_get_contents($p);
        if ($s === false) throw new StorageUnavailable('A backup file could not be read.');
        return $s;
    } finally {
        @unlink($p);
    }
}

/** @throws StorageNotFound when it does not exist */
function backupReadJson(StorageDriver $t, string $key): ?array
{
    $j = json_decode(backupReadString($t, $key), true);
    return is_array($j) ? $j : null;
}
