<?php
/**
 * The database part of a backup (#286): a full logical dump written in PHP
 * (the image has no mysqldump), and its replay.
 *
 * Format: gzip of a stream of SQL statements, each as a 4-byte big-endian length
 * followed by the statement. Replay runs them one by one without parsing SQL, so
 * quotes, semicolons and binary data inside values can never split a statement.
 *
 * The CALLER owns the transaction: backupDumpDatabase() must run inside
 * START TRANSACTION WITH CONSISTENT SNAPSHOT so every table is read at one moment.
 */

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
    $put = function (string $sql) use ($gz): void {
        $rec = pack('N', strlen($sql)) . $sql;
        if (gzwrite($gz, $rec) !== strlen($rec)) throw new RuntimeException('The database dump could not be written (is the disk full?).');
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
    $hex  = [];
    $q = $conn->prepare('SELECT COLUMN_NAME, DATA_TYPE, EXTRA FROM information_schema.COLUMNS
                          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION');
    $q->execute([$table]);
    foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $c) {
        if (stripos((string)$c['EXTRA'], 'GENERATED') !== false) continue;   // computed by the server on insert
        $cols[] = (string)$c['COLUMN_NAME'];
        $hex[]  = in_array(strtolower((string)$c['DATA_TYPE']),
                           ['binary', 'varbinary', 'tinyblob', 'blob', 'mediumblob', 'longblob', 'bit'], true);
    }
    if (!$cols) return 0;

    $head = 'INSERT INTO ' . backupIdent($table) . ' (' . implode(', ', array_map('backupIdent', $cols)) . ') VALUES ';
    $sel  = 'SELECT ' . implode(', ', array_map('backupIdent', $cols)) . ' FROM ' . backupIdent($table);

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
                elseif ($hex[$i])     $vals[] = $v === '' ? "''" : '0x' . bin2hex((string)$v);
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
 * Runs a dump's statements against $target.
 *
 * @return int  statements run
 * @throws RuntimeException  unreadable or truncated dump (statements already run stay run:
 *                           the caller restores into a database it may wipe)
 */
function backupReplayDump(PDO $target, string $inPath, ?callable $progress = null): int
{
    $gz = @gzopen($inPath, 'rb');
    if (!$gz) throw new RuntimeException('The database dump could not be opened.');
    $n = 0;
    try {
        while (true) {
            $len = backupGzRead($gz, 4);
            if ($len === '') break;
            if (strlen($len) !== 4) throw new RuntimeException('The database dump is truncated.');
            $size = unpack('N', $len)[1];
            $sql = backupGzRead($gz, $size);
            if (strlen($sql) !== $size) throw new RuntimeException('The database dump is truncated.');
            $target->exec($sql);
            $n++;
            if ($progress && $n % 200 === 0) $progress($n);
        }
    } finally {
        gzclose($gz);
    }
    return $n;
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
