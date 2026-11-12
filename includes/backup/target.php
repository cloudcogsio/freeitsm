<?php
/**
 * Backups (#286): where backups go, and the settings that describe it.
 *
 * The target is a folder on the server (a mounted NAS) or an S3-compatible bucket
 * with its OWN settings - separate from Files storage, so it can be offsite.
 * Everything lives under the store name "backup":
 *
 *   keyring.json                      the passphrase-locked keyring (safe to publish)
 *   sets/<YYYYMMDDTHHMMSSZ>/...       one backup set (see runner.php)
 *   pool/<name>, pool/<name>.key      every stored file once, encrypted; its sealed key
 *
 * A folder target is <folder>/backup/...; S3 is <prefix>backup/...
 */

require_once __DIR__ . '/../storage/driver.php';
require_once __DIR__ . '/../storage/local_driver.php';
require_once __DIR__ . '/../storage/s3_driver.php';
require_once __DIR__ . '/../encryption.php';

const BACKUP_SETTING_KEYS = [
    'backup_target', 'backup_folder',
    'backup_s3_endpoint', 'backup_s3_region', 'backup_s3_bucket', 'backup_s3_access_key_id',
    'backup_s3_secret', 'backup_s3_prefix', 'backup_s3_path_style',
    'backup_schedule', 'backup_weekday', 'backup_time', 'backup_keep_count',
    'backup_public_key', 'backup_keyring', 'backup_pool_name_secret', 'backup_install_id',
];

/** A system_settings value, or $default when unset. Throws when it cannot be read. */
function backupSetting(PDO $conn, string $key, string $default = ''): string
{
    $s = $conn->prepare('SELECT setting_value FROM system_settings WHERE setting_key = ?');
    $s->execute([$key]);
    $v = $s->fetchColumn();
    return $v === false || $v === null ? $default : (string)$v;
}

/** Saves a setting as given (encrypt secrets first); null removes it. */
function backupSaveSetting(PDO $conn, string $key, ?string $value): void
{
    if ($value === null) {
        $conn->prepare('DELETE FROM system_settings WHERE setting_key = ?')->execute([$key]);
        return;
    }
    $conn->prepare('INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)
                    ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)')->execute([$key, $value]);
}

/**
 * The saved target, or null when none is set.
 *
 * @return array|null ['type' => 'folder', 'folder' => ...] or
 *                    ['type' => 's3', endpoint, region, bucket, access_key_id, secret, prefix, path_style]
 */
function backupTargetConfig(PDO $conn): ?array
{
    $type = backupSetting($conn, 'backup_target');
    if ($type === 'folder') {
        $folder = backupSetting($conn, 'backup_folder');
        return $folder === '' ? null : ['type' => 'folder', 'folder' => $folder];
    }
    if ($type === 's3') {
        return [
            'type'          => 's3',
            'endpoint'      => backupSetting($conn, 'backup_s3_endpoint'),
            'region'        => backupSetting($conn, 'backup_s3_region', 'us-east-1'),
            'bucket'        => backupSetting($conn, 'backup_s3_bucket'),
            'access_key_id' => backupSetting($conn, 'backup_s3_access_key_id'),
            'secret'        => settingGetDecrypted($conn, 'backup_s3_secret'),
            'prefix'        => backupSetting($conn, 'backup_s3_prefix'),
            'path_style'    => backupSetting($conn, 'backup_s3_path_style') === '1',
        ];
    }
    return null;
}

/** The store for a target configuration (see backupTargetConfig()). */
function backupTargetDriver(array $cfg): StorageDriver&StorageLister
{
    if (($cfg['type'] ?? '') === 's3') {
        return new S3Driver(['driver' => 's3'] + $cfg, 'backup');
    }
    return new LocalDriver(rtrim(str_replace('\\', '/', (string)($cfg['folder'] ?? '')), '/') . '/backup');
}

/** The saved keyring (safe to publish), or null before a passphrase is set. */
function backupKeyring(PDO $conn): ?array
{
    $k = json_decode(backupSetting($conn, 'backup_keyring'), true);
    return is_array($k) ? $k : null;
}

/** The raw key that names pooled files (stored encrypted with the app key, so scheduled runs can use it). */
function backupPoolNameKey(PDO $conn): string
{
    $hex = settingGetDecrypted($conn, 'backup_pool_name_secret');
    $raw = $hex !== '' ? hex2bin($hex) : false;
    if ($raw === false || strlen($raw) !== 32) throw new RuntimeException('The backup pool name key is missing or unreadable (is the encryption key the one it was saved with?).');
    return $raw;
}

/**
 * Writes the keyring to the target, where a rebuild finds it with nothing but the
 * passphrase. A different keyring already there (another install's, or one from before
 * a rebuild) is kept beside it as keyring-<id>.json, never overwritten: the sets it
 * made still need it.
 */
function backupWriteKeyring(StorageDriver $target, array $keyring): void
{
    $tmp = tempnam(sys_get_temp_dir(), 'bkr');
    try {
        try {
            $target->readTo('keyring.json', $tmp);
            $old = json_decode((string)file_get_contents($tmp), true);
            if (is_array($old) && ($old['public'] ?? '') !== ($keyring['public'] ?? '') && ($old['public'] ?? '') !== '') {
                $target->putFile('keyring-' . substr(hash('sha256', (string)$old['public']), 0, 16) . '.json', $tmp);
            }
        } catch (StorageNotFound $e) {
            // first keyring on this target
        }
        file_put_contents($tmp, json_encode($keyring, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        $target->putFile('keyring.json', $tmp);
    } finally {
        @unlink($tmp);
    }
}
