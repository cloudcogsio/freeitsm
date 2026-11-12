<?php
/**
 * Backup encryption (#286). Everything a backup writes is encrypted here.
 *
 * A passphrase the app never stores protects one keypair. Scheduled backups only
 * need the PUBLIC half (in settings): every backup set and every pooled file gets
 * a random key, sealed to the public key and stored beside it. Opening anything -
 * verify, restore - needs the passphrase, which unlocks the secret half.
 *
 * Bulk data is crypto_secretstream_xchacha20poly1305 in 64 KiB chunks, so files of
 * any size stream, and a truncated or altered object is detected: every chunk is
 * authenticated and only the last carries TAG_FINAL.
 *
 * An encrypted object: "FIBK" + version byte (1) + secretstream header (24 bytes)
 * + chunks of (plaintext, at most 64 KiB) + 17 bytes.
 */

class BackupWrongPassphrase extends RuntimeException {}
class BackupCorrupt extends RuntimeException {}

const BACKUP_MAGIC = "FIBK\x01";
const BACKUP_CHUNK = 65536;

function backupSodiumAvailable(): bool
{
    return function_exists('sodium_crypto_box_seal') && function_exists('sodium_crypto_pwhash')
        && function_exists('sodium_crypto_secretstream_xchacha20poly1305_init_push');
}

/** Exact size of backupEncryptFile()'s output for a plaintext of $plainSize bytes. */
function backupEncryptedSize(int $plainSize): int
{
    $chunks = max(1, intdiv($plainSize + BACKUP_CHUNK - 1, BACKUP_CHUNK));
    return strlen(BACKUP_MAGIC) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
         + $plainSize + $chunks * SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
}

// ── Keyring ──

/**
 * A new keypair and pool name key, locked with $passphrase.
 *
 * @return array{public: string, keyring: array, pool_name_key: string}
 *         public = base64; keyring = safe to publish (bucket, settings); pool_name_key = raw
 */
function backupNewKeyring(string $passphrase, ?int $ops = null, ?int $mem = null): array
{
    $pair   = sodium_crypto_box_keypair();
    $public = sodium_crypto_box_publickey($pair);
    $secret = sodium_crypto_box_secretkey($pair);
    $pool   = random_bytes(32);
    $keyring = backupLockKeyring($public, $secret, $pool, $passphrase,
                                 $ops ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                                 $mem ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE);
    sodium_memzero($secret);
    sodium_memzero($pair);
    return ['public' => base64_encode($public), 'keyring' => $keyring, 'pool_name_key' => $pool];
}

function backupLockKeyring(string $public, string $secret, string $pool, string $passphrase, int $ops, int $mem): array
{
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $k    = backupPassphraseKey($passphrase, $salt, $ops, $mem);
    $n1   = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $n2   = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $out = [
        'v'            => 1,
        'salt'         => base64_encode($salt),
        'ops'          => $ops,
        'mem'          => $mem,
        'public'       => base64_encode($public),
        'secret_enc'   => base64_encode($n1 . sodium_crypto_secretbox($secret, $n1, $k)),
        'pool_key_enc' => base64_encode($n2 . sodium_crypto_secretbox($pool, $n2, $k)),
    ];
    sodium_memzero($k);
    return $out;
}

function backupPassphraseKey(string $passphrase, string $salt, int $ops, int $mem): string
{
    return sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $passphrase, $salt, $ops, $mem,
                                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
}

/**
 * @return array{public: string, secret: string, pool_name_key: string}  all raw
 * @throws BackupWrongPassphrase  the passphrase does not open it
 * @throws BackupCorrupt          it is not a keyring
 */
function backupUnlockKeyring(array $keyring, string $passphrase): array
{
    $nb   = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
    $salt = base64_decode((string)($keyring['salt'] ?? ''), true);
    $pub  = base64_decode((string)($keyring['public'] ?? ''), true);
    $se   = base64_decode((string)($keyring['secret_enc'] ?? ''), true);
    $pe   = base64_decode((string)($keyring['pool_key_enc'] ?? ''), true);
    $ops  = (int)($keyring['ops'] ?? 0);
    $mem  = (int)($keyring['mem'] ?? 0);
    if ((int)($keyring['v'] ?? 0) !== 1 || !is_string($salt) || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES
        || !is_string($pub) || strlen($pub) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES
        || !is_string($se) || strlen($se) <= $nb || !is_string($pe) || strlen($pe) <= $nb
        || $ops < 1 || $mem < 8192) {
        throw new BackupCorrupt('The backup keyring is not readable.');
    }
    $k = backupPassphraseKey($passphrase, $salt, $ops, $mem);
    $secret = sodium_crypto_secretbox_open(substr($se, $nb), substr($se, 0, $nb), $k);
    $pool   = $secret === false ? false : sodium_crypto_secretbox_open(substr($pe, $nb), substr($pe, 0, $nb), $k);
    sodium_memzero($k);
    if ($secret === false || $pool === false) throw new BackupWrongPassphrase('The backup passphrase is not correct.');
    return ['public' => $pub, 'secret' => $secret, 'pool_name_key' => $pool];
}

/** The same keys under a new passphrase and salt: every existing backup opens with the new one. */
function backupRekeyKeyring(array $keyring, string $old, string $new): array
{
    $keys = backupUnlockKeyring($keyring, $old);
    $out = backupLockKeyring($keys['public'], $keys['secret'], $keys['pool_name_key'], $new,
                             (int)$keyring['ops'], (int)$keyring['mem']);
    sodium_memzero($keys['secret']);
    return $out;
}

/** Opaque, stable name for a pooled file: nothing in the bucket shows its real hash. */
function backupPoolName(string $poolNameKey, string $sha256hex): string
{
    return hash_hmac('sha256', strtolower($sha256hex), $poolNameKey);
}

// ── Sealed keys ──

function backupSealKey(string $key, string $publicRaw): string
{
    return sodium_crypto_box_seal($key, $publicRaw);
}

/** @throws BackupCorrupt */
function backupOpenKey(string $sealed, string $publicRaw, string $secretRaw): string
{
    $pair = sodium_crypto_box_keypair_from_secretkey_and_publickey($secretRaw, $publicRaw);
    try {
        $key = sodium_crypto_box_seal_open($sealed, $pair);
    } catch (SodiumException $e) {
        $key = false;
    }
    sodium_memzero($pair);
    if ($key === false) throw new BackupCorrupt('A backup key could not be opened.');
    return $key;
}

// ── Streams ──

/**
 * Encrypts file $in into $out under $key.
 *
 * @return int  bytes written (always backupEncryptedSize(filesize($in)))
 */
function backupEncryptFile(string $in, string $out, string $key): int
{
    $src = @fopen($in, 'rb');
    if (!$src) throw new RuntimeException('A file to back up could not be read.');
    $dst = @fopen($out, 'wb');
    if (!$dst) { fclose($src); throw new RuntimeException('The backup temporary folder is not writable.'); }
    $ok = false;
    try {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $written = backupWriteAll($dst, BACKUP_MAGIC . $header);
        $chunk = backupReadChunk($src, BACKUP_CHUNK);
        while (true) {
            $next = backupReadChunk($src, BACKUP_CHUNK);
            $last = $next === '';
            $tag  = $last ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                          : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            $written += backupWriteAll($dst, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag));
            if ($last) break;
            $chunk = $next;
        }
        sodium_memzero($state);
        $ok = true;
    } finally {
        fclose($src);
        $closed = fclose($dst);
        if ($ok && $closed === false) throw new RuntimeException('The backup temporary file could not be written.');
    }
    return $written;
}

/**
 * Decrypts file $in into $out, or only checks it when $out is null.
 *
 * @return string  SHA-256 (hex) of the plaintext
 * @throws BackupCorrupt  altered, truncated, the wrong key, or not a backup object
 */
function backupDecryptFile(string $in, ?string $out, string $key): string
{
    $src = @fopen($in, 'rb');
    if (!$src) throw new RuntimeException('A backup file could not be read.');
    $dst = null;
    if ($out !== null) {
        $dst = @fopen($out, 'wb');
        if (!$dst) { fclose($src); throw new RuntimeException('The restore target is not writable.'); }
    }
    $hash = hash_init('sha256');
    $headLen = strlen(BACKUP_MAGIC) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
    $ok = false;
    try {
        $head = backupReadChunk($src, $headLen);
        if (strlen($head) !== $headLen || substr($head, 0, strlen(BACKUP_MAGIC)) !== BACKUP_MAGIC) {
            throw new BackupCorrupt('Not a FreeITSM backup object.');
        }
        try {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($head, strlen(BACKUP_MAGIC)), $key);
        } catch (SodiumException $e) {
            throw new BackupCorrupt('Not a FreeITSM backup object.');
        }
        $final = false;
        while (!$final) {
            $c = backupReadChunk($src, BACKUP_CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            if ($c === '') throw new BackupCorrupt('The backup object is truncated.');
            try {
                $r = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $c);
            } catch (SodiumException $e) {
                $r = false;
            }
            if ($r === false) throw new BackupCorrupt('The backup object is damaged or was encrypted with another key.');
            [$plain, $tag] = $r;
            hash_update($hash, $plain);
            if ($dst) backupWriteAll($dst, $plain);
            $final = $tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
        }
        if (backupReadChunk($src, 1) !== '') throw new BackupCorrupt('The backup object has data after its end.');
        $ok = true;
    } finally {
        fclose($src);
        $closed = $dst ? fclose($dst) : true;
        if ($ok && $closed === false) throw new RuntimeException('The restore target could not be written.');
    }
    return hash_final($hash);
}

function backupEncryptString(string $plain, string $key): string
{
    $in  = tempnam(sys_get_temp_dir(), 'bke');
    $out = tempnam(sys_get_temp_dir(), 'bke');
    try {
        file_put_contents($in, $plain);
        backupEncryptFile($in, $out, $key);
        return (string)file_get_contents($out);
    } finally {
        @unlink($in);
        @unlink($out);
    }
}

/** @throws BackupCorrupt */
function backupDecryptString(string $enc, string $key): string
{
    $in  = tempnam(sys_get_temp_dir(), 'bkd');
    $out = tempnam(sys_get_temp_dir(), 'bkd');
    try {
        file_put_contents($in, $enc);
        backupDecryptFile($in, $out, $key);
        return (string)file_get_contents($out);
    } finally {
        @unlink($in);
        @unlink($out);
    }
}

/** Up to $n bytes; fewer only at the end of the file. */
function backupReadChunk($fh, int $n): string
{
    $buf = '';
    while (strlen($buf) < $n && !feof($fh)) {
        $r = fread($fh, $n - strlen($buf));
        if ($r === false) throw new RuntimeException('A file could not be read.');
        if ($r === '') break;
        $buf .= $r;
    }
    return $buf;
}

function backupWriteAll($fh, string $data): int
{
    $len = strlen($data);
    for ($done = 0; $done < $len; $done += $w) {
        $w = @fwrite($fh, $done ? substr($data, $done) : $data);
        if ($w === false || $w === 0) throw new RuntimeException('The disk is full or a file could not be written.');
    }
    return $len;
}
