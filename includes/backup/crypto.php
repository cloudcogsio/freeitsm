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
/** Size of a sealed 32-byte key (pool/<name>.key, datakey.bin). */
const BACKUP_SEALED_KEY_SIZE = SODIUM_CRYPTO_BOX_SEALBYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;

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

/**
 * @param array $previous  earlier keypairs ([['public' => raw, 'secret' => raw], ...], newest first):
 *                         the pool objects and sets made before a passphrase change were sealed to
 *                         them, so the current passphrase must open them too
 */
function backupLockKeyring(string $public, string $secret, string $pool, string $passphrase, int $ops, int $mem, array $previous = []): array
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
    if ($previous) {
        $n3 = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = json_encode(array_map(fn($p) => [base64_encode($p['public']), base64_encode($p['secret'])], array_values($previous)));
        $out['previous_enc'] = base64_encode($n3 . sodium_crypto_secretbox($plain, $n3, $k));
        sodium_memzero($plain);
    }
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
    $previous = [];
    if ($secret !== false && $pool !== false && isset($keyring['previous_enc'])) {
        $ve = base64_decode((string)$keyring['previous_enc'], true);
        $plain = is_string($ve) && strlen($ve) > $nb ? sodium_crypto_secretbox_open(substr($ve, $nb), substr($ve, 0, $nb), $k) : false;
        $list = $plain === false ? null : json_decode($plain, true);
        if (!is_array($list)) { sodium_memzero($k); throw new BackupCorrupt('The backup keyring is not readable.'); }
        foreach ($list as $p) {
            $previous[] = ['public' => (string)base64_decode((string)($p[0] ?? ''), true), 'secret' => (string)base64_decode((string)($p[1] ?? ''), true)];
        }
        sodium_memzero($plain);
    }
    sodium_memzero($k);
    if ($secret === false || $pool === false) throw new BackupWrongPassphrase('The backup passphrase is not correct.');
    return ['public' => $pub, 'secret' => $secret, 'pool_name_key' => $pool, 'previous' => $previous];
}

/**
 * A passphrase change: a NEW keypair, locked with the new passphrase, for everything backed up
 * from now on - so the old passphrase opens nothing made after the change. The pool name key
 * stays (files already pooled are reused, not uploaded again), and the earlier keypairs travel
 * inside, under the new passphrase, so it opens the older backups and pooled files too.
 *
 * What the OLD passphrase still opens: the backups made before the change (each keeps its copy
 * of the keyring it was made with, and the target keeps the old keyring beside the new one),
 * and the pooled files sealed before the change - including those a newer backup reuses.
 *
 * @return array{keyring: array, public: string}  public = the new public key, base64
 * @throws BackupWrongPassphrase  the old passphrase does not open $keyring
 */
function backupChangeKeyring(array $keyring, string $old, string $new): array
{
    $keys = backupUnlockKeyring($keyring, $old);
    $pair = sodium_crypto_box_keypair();
    $public = sodium_crypto_box_publickey($pair);
    $secret = sodium_crypto_box_secretkey($pair);
    $previous = array_merge([['public' => $keys['public'], 'secret' => $keys['secret']]], $keys['previous']);
    $out = backupLockKeyring($public, $secret, $keys['pool_name_key'], $new, (int)$keyring['ops'], (int)$keyring['mem'], $previous);
    sodium_memzero($secret);
    sodium_memzero($pair);
    backupForgetKeys($keys);
    return ['keyring' => $out, 'public' => base64_encode($public)];
}

/** Wipes the secret halves of unlocked keys (backupUnlockKeyring()). */
function backupForgetKeys(array &$keys): void
{
    if (isset($keys['secret']) && is_string($keys['secret'])) sodium_memzero($keys['secret']);
    foreach ($keys['previous'] ?? [] as $i => $p) {
        if (is_string($p['secret'] ?? null)) sodium_memzero($keys['previous'][$i]['secret']);
    }
}

/**
 * Opens a sealed key with the current keypair or, failing that, an earlier one (a pool object or
 * set sealed before a passphrase change).
 *
 * @throws BackupCorrupt  none of them opens it
 */
function backupOpenKeyAny(string $sealed, array $keys): string
{
    foreach (array_merge([['public' => $keys['public'], 'secret' => $keys['secret']]], $keys['previous'] ?? []) as $p) {
        try {
            return backupOpenKey($sealed, $p['public'], $p['secret']);
        } catch (BackupCorrupt $e) {
            // try the next one
        }
    }
    throw new BackupCorrupt('A backup key could not be opened.');
}

/** Opaque, stable name for a pooled file: nothing in the bucket shows its real hash. */
function backupPoolName(string $poolNameKey, string $sha256hex): string
{
    return hash_hmac('sha256', strtolower($sha256hex), $poolNameKey);
}

/**
 * Proof a set was made by an install holding the pool name key - which someone with
 * only bucket access (and the published public key) does not have. Covers the sealed
 * data key and the encrypted manifest; the manifest pins every other checksum.
 */
function backupSetAuth(string $poolNameKey, string $set, string $datakeyBin, string $manifestSha256): string
{
    return hash_hmac('sha256', "FIBK-set-v1\n$set\n" . hash('sha256', $datakeyBin) . "\n" . $manifestSha256,
                     hash_hmac('sha256', 'set-auth', $poolNameKey, true));
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
 * @param string|null $plainSha256  set to the SHA-256 (hex) of the bytes actually encrypted
 * @param int|null    $plainSize    set to how many bytes were encrypted
 * @return int  bytes written (always backupEncryptedSize($plainSize))
 */
function backupEncryptFile(string $in, string $out, string $key, ?string &$plainSha256 = null, ?int &$plainSize = null): int
{
    $hash = hash_init('sha256');
    $plainSize = 0;
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
            hash_update($hash, $chunk);
            $plainSize += strlen($chunk);
            $written += backupWriteAll($dst, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag));
            if ($last) break;
            $chunk = $next;
        }
        sodium_memzero($state);
        $plainSha256 = hash_final($hash);
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
