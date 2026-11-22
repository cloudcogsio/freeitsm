<?php
/**
 * The database part of a backup (#286): a full logical dump written in PHP
 * (the image has no mysqldump), and its replay.
 *
 * Format: gzip of a stream of SQL statements, each as a 4-byte big-endian length
 * followed by the statement. Replay runs them one by one without parsing SQL, so
 * quotes, semicolons and binary data inside values can never split a statement.
 *
 * The last record is the end record: BACKUP_DUMP_END followed by the number of
 * statements before it. Without it, a dump cut off exactly between two statements is
 * a well-formed, shorter dump that replays "successfully" with part of the data, so
 * a dump without its end record is refused (backupCheckDump(), backupReplayDump()).
 *
 * The CALLER owns the transaction: backupDumpDatabase() must run inside
 * START TRANSACTION WITH CONSISTENT SNAPSHOT so every table is read at one moment.
 */

/** The end record's prefix. Never the start of a real statement (those are SET, DROP, CREATE, INSERT). */
const BACKUP_DUMP_END = '-- FreeITSM dump end ';

const BACKUP_DUMP_INCOMPLETE = 'The database dump is incomplete: its end record is missing, so part of the data would be lost.';

/**
 * @param int|null $batchBytes  largest INSERT to write (default: half of max_allowed_packet, at most 4 MiB);
 *                              a single row larger than this still goes out, on its own
 * @return array{tables: array<string,int>, bytes: int}  rows per table, size of the dump file
 */
function backupDumpDatabase(PDO $conn, string $outPath, ?int $batchBytes = null): array
{
    if (!$conn->inTransaction()) {
        throw new LogicException('The dump must run inside a consistent-snapshot transaction.');
    }
    if ($batchBytes === null) {
        $packet = (int)$conn->query('SELECT @@max_allowed_packet')->fetchColumn();
        $batchBytes = (int)max(64 * 1024, min(4 * 1024 * 1024, intdiv($packet, 2)));
    }

    $gz = @gzopen($outPath, 'wb6');
    if (!$gz) throw new RuntimeException('The backup temporary folder is not writable.');
    $statements = 0;
    $put = function (string $sql) use ($gz, &$statements): void {
        $rec = pack('N', strlen($sql)) . $sql;
        if (gzwrite($gz, $rec) !== strlen($rec)) throw new RuntimeException('The database dump could not be written (is the disk full?).');
        $statements++;
    };

    $counts = [];
    $buffered = $conn->getAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY);
    try {
        $put('SET NAMES utf8mb4');
        $put("SET time_zone = '+00:00'");
        $put('SET FOREIGN_KEY_CHECKS = 0');
        $put('SET UNIQUE_CHECKS = 0');
        $put("SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'");

        $all    = $conn->query('SHOW FULL TABLES')->fetchAll(PDO::FETCH_NUM);
        $tables = array_values(array_map(fn($r) => (string)$r[0], array_filter($all, fn($r) => $r[1] === 'BASE TABLE')));
        $views  = array_values(array_map(fn($r) => (string)$r[0], array_filter($all, fn($r) => $r[1] === 'VIEW')));

        foreach ($views as $v) $put('DROP VIEW IF EXISTS ' . backupIdent($v));
        foreach ($tables as $t) {
            $create = $conn->query('SHOW CREATE TABLE ' . backupIdent($t))->fetch(PDO::FETCH_NUM)[1];
            $put('DROP TABLE IF EXISTS ' . backupIdent($t));
            $put($create);
            $counts[$t] = backupDumpRows($conn, $t, $batchBytes, $put);
        }
        foreach ($views as $v) {
            $create = (string)$conn->query('SHOW CREATE VIEW ' . backupIdent($v))->fetch(PDO::FETCH_NUM)[1];
            $put(backupStripDefiner($create));
        }
        foreach ($conn->query('SHOW TRIGGERS')->fetchAll(PDO::FETCH_ASSOC) as $tr) {
            $name = (string)$tr['Trigger'];
            $row = $conn->query('SHOW CREATE TRIGGER ' . backupIdent($name))->fetch(PDO::FETCH_ASSOC);
            $put('DROP TRIGGER IF EXISTS ' . backupIdent($name));
            $put(backupStripDefiner((string)$row['SQL Original Statement']));
        }
        $put('SET UNIQUE_CHECKS = 1');
        $put('SET FOREIGN_KEY_CHECKS = 1');
        $put(BACKUP_DUMP_END . $statements);   // last: the dump is complete
    } finally {
        $conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, $buffered);
        $closed = gzclose($gz);
    }
    if ($closed === false) throw new RuntimeException('The database dump could not be written (is the disk full?).');
    clearstatcache(true, $outPath);
    return ['tables' => $counts, 'bytes' => (int)filesize($outPath)];
}

/** Writes a table's rows as batched INSERTs; returns the row count. */
function backupDumpRows(PDO $conn, string $table, int $batchBytes, callable $put): int
{
    $cols = [];
    $kind = [];   // per column: 'bin' (escaped _binary string), 'bit' (b'...' literal) or 'text'
    $q = $conn->prepare('SELECT COLUMN_NAME, DATA_TYPE, EXTRA, GENERATION_EXPRESSION FROM information_schema.COLUMNS
                          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION');
    $q->execute([$table]);
    foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $c) {
        // Only a real generated column (VIRTUAL or STORED) is computed by the server on insert.
        // NOT "DEFAULT_GENERATED", which MySQL 8.0.13+ reports for every DEFAULT CURRENT_TIMESTAMP
        // column: those hold data (created_datetime...) and must be dumped.
        if (trim((string)($c['GENERATION_EXPRESSION'] ?? '')) !== '' || preg_match('/\b(VIRTUAL|STORED) GENERATED\b/i', (string)$c['EXTRA'])) continue;
        $cols[] = (string)$c['COLUMN_NAME'];
        $type = strtolower((string)$c['DATA_TYPE']);
        $kind[] = $type === 'bit' ? 'bit'
                : (in_array($type, ['binary', 'varbinary', 'tinyblob', 'blob', 'mediumblob', 'longblob'], true) ? 'bin' : 'text');
    }
    if (!$cols) return 0;

    $head = 'INSERT INTO ' . backupIdent($table) . ' (' . implode(', ', array_map('backupIdent', $cols)) . ') VALUES ';
    // A BIT column is read as its number (the text protocol would hand back the digits as a string)
    // and written back as that number: a quoted string would be stored as its characters' bytes.
    $sel  = 'SELECT ' . implode(', ', array_map(fn($c, $k) => $k === 'bit' ? 'CAST(' . backupIdent($c) . ' AS UNSIGNED)' : backupIdent($c), $cols, $kind))
          . ' FROM ' . backupIdent($table);

    // Unbuffered: a large table streams instead of being held in memory. Nothing else
    // may run on this connection until the cursor is closed.
    $conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
    $rows = 0;
    $batch = '';
    try {
        $st = $conn->query($sel, PDO::FETCH_NUM);
        foreach ($st as $r) {
            $vals = [];
            foreach ($r as $i => $v) {
                if ($v === null)      $vals[] = 'NULL';
                elseif ($kind[$i] === 'bit') $vals[] = ctype_digit((string)$v) ? (string)$v : '0';
                elseif ($kind[$i] === 'bin') $vals[] = $v === '' ? "''" : '_binary' . $conn->quote((string)$v);   // escaped, not hex: hex doubles a row, which then may not fit max_allowed_packet on restore
                else                  $vals[] = $conn->quote((string)$v);
            }
            $tuple = '(' . implode(', ', $vals) . ')';
            if ($batch !== '' && strlen($batch) + strlen($tuple) + 2 > $batchBytes) {
                $put($batch);
                $batch = '';
            }
            $batch .= ($batch === '' ? $head : ', ') . $tuple;
            $rows++;
        }
        $st->closeCursor();
    } finally {
        $conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
    }
    if ($batch !== '') $put($batch);
    return $rows;
}

/**
 * Reads a whole dump without running anything: is it complete?
 *
 * @return array{statements: int, ended: bool}  statements before the end record, and whether
 *                                               the end record is there (false: a dump made before
 *                                               end records existed, or one cut off between statements)
 * @throws RuntimeException  unreadable, cut off inside a record, or an end record that does not
 *                           count what came before it or is not the last thing in the dump
 */
function backupCheckDump(string $inPath): array
{
    $gz = @gzopen($inPath, 'rb');
    if (!$gz) throw new RuntimeException('The database dump could not be opened.');
    $n = 0;
    $ended = false;
    try {
        while (($sql = backupDumpNext($gz)) !== null) {
            if (backupDumpIsEnd($gz, $sql, $n)) { $ended = true; break; }
            $n++;
        }
    } finally {
        gzclose($gz);
    }
    return ['statements' => $n, 'ended' => $ended];
}

/**
 * Runs a dump's statements against $target.
 *
 * @param int|null $maxPacket  the server's max_allowed_packet (default: asked); tests pass a small one
 * @return int  statements run
 * @throws RuntimeException  unreadable, truncated or incomplete dump, or a statement the server will not
 *                           take (statements already run stay run: the caller restores into a database it
 *                           may wipe, and checks the dump with backupCheckDump() before it wipes anything)
 */
function backupReplayDump(PDO $target, string $inPath, ?callable $progress = null, ?int $maxPacket = null): int
{
    $gz = @gzopen($inPath, 'rb');
    if (!$gz) throw new RuntimeException('The database dump could not be opened.');
    $maxPacket ??= (int)$target->query('SELECT @@max_allowed_packet')->fetchColumn();
    $n = 0;
    $ended = false;
    try {
        while (($sql = backupDumpNext($gz)) !== null) {
            if (backupDumpIsEnd($gz, $sql, $n)) { $ended = true; break; }
            $size = strlen($sql);
            if ($maxPacket > 0 && $size + 1024 > $maxPacket) {
                $table = preg_match('/^INSERT INTO `((?:[^`]|``)+)`/', $sql, $m) ? str_replace('``', '`', $m[1]) : '?';
                throw new RuntimeException(sprintf(
                    'A row of table %s needs %.1f MB, more than this MySQL server accepts (max_allowed_packet = %.1f MB). '
                    . 'Raise max_allowed_packet on the server (for example --max-allowed-packet=%dM) and run the restore again.',
                    $table, $size / 1048576, $maxPacket / 1048576, (int)ceil(($size + 1024) / 1048576) * 2));
            }
            $target->exec($sql);
            $n++;
            if ($progress && $n % 200 === 0) $progress($n);
        }
    } finally {
        gzclose($gz);
    }
    if (!$ended) throw new RuntimeException(BACKUP_DUMP_INCOMPLETE);
    return $n;
}

/** The next statement, or null at the end of the stream. A record cut off part way throws. */
function backupDumpNext($gz): ?string
{
    $len = backupGzRead($gz, 4);
    if ($len === '') return null;
    if (strlen($len) !== 4) throw new RuntimeException('The database dump is truncated.');
    $size = unpack('N', $len)[1];
    $sql = backupGzRead($gz, $size);
    if (strlen($sql) !== $size) throw new RuntimeException('The database dump is truncated.');
    return $sql;
}

/**
 * Is $sql the end record? A real one counts the $before statements ahead of it and is the
 * last thing in the stream; anything else that claims to be one is damage.
 */
function backupDumpIsEnd($gz, string $sql, int $before): bool
{
    if (!str_starts_with($sql, BACKUP_DUMP_END)) return false;
    if ($sql !== BACKUP_DUMP_END . $before || backupGzRead($gz, 1) !== '') {
        throw new RuntimeException('The database dump is damaged: its end record does not match its contents.');
    }
    return true;
}

/** Exactly $n bytes unless the stream ends first. A damaged gzip stream throws. */
function backupGzRead($gz, int $n): string
{
    $buf = '';
    while (strlen($buf) < $n) {
        $r = gzread($gz, $n - strlen($buf));
        if ($r === false) throw new RuntimeException('The database dump is damaged.');
        if ($r === '') break;
        $buf .= $r;
    }
    return $buf;
}

function backupIdent(string $name): string
{
    return '`' . str_replace('`', '``', $name) . '`';
}

/** A view or trigger restored on another server must not name this server's account. */
function backupStripDefiner(string $sql): string
{
    return (string)preg_replace('/\sDEFINER\s*=\s*(`[^`]*`|\'[^\']*\'|\S+)@(`[^`]*`|\'[^\']*\'|\S+)/i', '', $sql, 1);
}
