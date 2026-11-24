<?php
/**
 * TaskHistory - the record a task keeps of what happened to it (#181).
 *
 * Before this, Tasks kept a task's CURRENT state and almost none of its history:
 * who completed it was not stored, reopening erased its completion time, a
 * repeat's rule was overwritten in place and a deleted occurrence vanished. An
 * auditor's question - "show me this check was done every month this year" -
 * could not be answered from that. This class writes the history; the evidence
 * report (includes/task_evidence.php) reads it.
 *
 * Writes three append-only tables, none with a foreign key (see freeitsm.sql):
 *   task_events               one row per thing that happened to a task
 *   task_recurrence_versions  every version of a repeat's rule
 *   task_removed_records      a deleted occurrence, frozen with everything the report reads
 *
 * 🔴 THE ONE STATUS HOOK. A task's status is written in four places - the task
 * window and the REST API (TasksService::updateTask), the REST move
 * (TasksService::moveTask), the board's drag (api/tasks/reorder.php) and the
 * subtask tick (api/tasks/toggle_subtask.php). Every one of them calls
 * afterStatusChange(), which records the change, who completed it, and - for a
 * repeat set to "after completion" - makes the next occurrence. Before #181 the
 * board's drag never made the next occurrence at all, because only two of the
 * four paths remembered to. A fifth status writer MUST call afterStatusChange().
 *
 * Recording never breaks the change it records: every write here swallows its
 * own errors (and logs them), exactly as task_audit always has.
 */

require_once __DIR__ . '/../service_context.php';

final class TaskHistory
{
    /**
     * Who did it, as stored: [analyst_id or null, actor_kind, actor_name].
     * No context means the system - the repeat, a background job.
     */
    public static function actor(?ActorContext $ctx): array
    {
        if ($ctx === null) return [null, 'system', null];
        if ($ctx->actorId > 0) {
            return [$ctx->actorId, $ctx->source === 'api' ? 'api' : 'analyst', $ctx->actorName !== '' ? $ctx->actorName : null];
        }
        $kind = in_array($ctx->source, ['portal', 'workflow', 'api'], true) ? $ctx->source : 'system';
        return [null, $kind, $ctx->actorName !== '' ? $ctx->actorName : null];
    }

    /**
     * Records one event on a task.
     *
     * @param string $type  created, status_changed, completed, reopened, due_date_changed, start_date_changed,
     *     assigned, team_assigned, skipped, successor, checklist_attached, checklist_removed, evidence_exported, removed
     * @param ?ActorContext $ctx  who did it; null for the system (then the current background job run is linked)
     * @param mixed $from  the value before, or null
     * @param mixed $to  the value after, or null
     * @param array $detail  anything else worth keeping, stored as JSON
     * @param ?int $recurrenceId  the series; looked up from the task when null
     */
    public static function record(PDO $conn, int $taskId, string $type, ?ActorContext $ctx, $from = null, $to = null,
                                  array $detail = [], ?int $recurrenceId = null): void
    {
        try {
            self::write($conn, $taskId, $type, $ctx, $from, $to, $detail, $recurrenceId);
        } catch (Throwable $e) {
            error_log('[task history] could not record ' . $type . ' on task ' . $taskId . ': ' . $e->getMessage());
        }
    }

    /**
     * TEST HOOK (#181 follow-up): the event type whose next STRICT write throws, or '*' for any.
     * Set only by tests/task-evidence-atomic.php, in its own CLI process - never by the app.
     */
    public static ?string $failNextWrite = null;

    /** Has Database Verification created the history tables? Cached per request. Before it, there is no evidence to keep. */
    public static function ready(PDO $conn): bool
    {
        static $ready = null;
        if ($ready !== null) return $ready;
        try {
            $conn->query("SELECT id FROM task_events LIMIT 0");
            $conn->query("SELECT completed_by_id, skipped_datetime FROM tasks LIMIT 0");
            $conn->query("SELECT id FROM task_removed_records LIMIT 0");
            return $ready = true;
        } catch (Throwable) {
            return $ready = false;
        }
    }

    /**
     * Records one event as EVIDENCE: inside the caller's transaction, and a failure is the
     * caller's failure (GH #181, Dr4inder's review). The change and its record are saved
     * together or not at all - "usually recorded" is not evidence.
     *
     * @throws ServiceError evidence_not_recorded when the write fails
     */
    public static function recordStrict(PDO $conn, int $taskId, string $type, ?ActorContext $ctx, $from = null, $to = null,
                                        array $detail = [], ?int $recurrenceId = null): void
    {
        if (!self::ready($conn)) return;          // no history tables yet: nothing to keep, nothing to fail
        try {
            self::write($conn, $taskId, $type, $ctx, $from, $to, $detail, $recurrenceId);
        } catch (Throwable $e) {
            throw self::notRecorded($type, $e);
        }
    }

    /** The error a failed evidence write becomes. Nothing was changed - say so. */
    public static function notRecorded(string $what, Throwable $e): ServiceError
    {
        error_log('[task history] evidence not recorded (' . $what . '): ' . $e->getMessage());
        return new ServiceError('conflict', 'evidence_not_recorded',
            function_exists('t') ? t('tasks.history.not_recorded') : 'Nothing was changed: the record of this change could not be saved. Try again, and tell your administrator if it keeps happening.');
    }

    /** The one INSERT behind record() and recordStrict(). Throws. */
    private static function write(PDO $conn, int $taskId, string $type, ?ActorContext $ctx, $from, $to,
                                  array $detail, ?int $recurrenceId): void
    {
        if (self::$failNextWrite !== null && (self::$failNextWrite === '*' || self::$failNextWrite === $type)) {
            self::$failNextWrite = null;
            throw new RuntimeException('injected failure (test)');
        }
        {
            if ($recurrenceId === null) {
                $r = $conn->prepare("SELECT recurrence_id FROM tasks WHERE id = ?");
                $r->execute([$taskId]);
                $v = $r->fetchColumn();
                $recurrenceId = $v ? (int)$v : null;
            }
            [$aid, $kind, $name] = self::actor($ctx);
            if ($aid !== null && $name === null) $name = self::analystName($conn, $aid);
            $runId = ($ctx === null && class_exists('JobRun')) ? JobRun::current() : null;
            $conn->prepare("INSERT INTO task_events (task_id, recurrence_id, event_type, analyst_id, actor_kind, actor_name,
                                                     from_value, to_value, detail_json, job_run_id, created_datetime)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())")
                 ->execute([$taskId, $recurrenceId, $type, $aid, $kind, $name,
                            $from === null ? null : mb_substr((string)$from, 0, 255),
                            $to === null ? null : mb_substr((string)$to, 0, 255),
                            $detail ? json_encode($detail, JSON_UNESCAPED_UNICODE) : null, $runId]);
        }
    }

    /**
     * The task as the status hook needs it, read BEFORE the change.
     *
     * @param int $taskId  the task about to change
     */
    public static function before(PDO $conn, int $taskId): array
    {
        try {
            $s = $conn->prepare("SELECT t.id, t.status_id, t.due_date, t.recurrence_id, t.parent_task_id, t.completed_datetime,
                                        t.scheduled_date, t.completed_by_id, t.skipped_datetime,
                                        ts.name AS status_name, ts.is_closed AS status_is_closed
                                   FROM tasks t LEFT JOIN task_statuses ts ON ts.id = t.status_id WHERE t.id = ?");
            $s->execute([$taskId]);
            return $s->fetch(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable) {
            // Before Database Verification has added the #181 columns.
            $s = $conn->prepare("SELECT t.id, t.status_id, t.due_date, t.recurrence_id, t.parent_task_id, t.completed_datetime,
                                        ts.name AS status_name, ts.is_closed AS status_is_closed
                                   FROM tasks t LEFT JOIN task_statuses ts ON ts.id = t.status_id WHERE t.id = ?");
            $s->execute([$taskId]);
            return $s->fetch(PDO::FETCH_ASSOC) ?: [];
        }
    }

    /**
     * THE status hook - call after ANY write that changes a task's status, outside any transaction.
     *
     * Records the change; on completing, who completed it and the due date in force (so a later edit
     * to the due date cannot change how the completion is judged); on reopening, the completion it
     * undid. Then, for a repeat set to "after completion", makes the next occurrence - and records
     * that one was expected BEFORE trying, so a failure to create it is still on the record.
     *
     * @param array $before  TaskHistory::before() as read before the write
     * @param int $newStatusId  the status the task is now in
     * @param ?string $skipReason  set when this change is a SKIP (TasksService::skipOccurrence): recorded as skipped, not completed
     */
    public static function afterStatusChange(PDO $conn, ?ActorContext $ctx, int $taskId, array $before, int $newStatusId,
                                             ?string $skipReason = null): void
    {
        // Kept for any caller that writes the status itself: the evidence in its own
        // transaction, then the successor. The four status writers use the two halves.
        $own = !$conn->inTransaction();
        if ($own) $conn->beginTransaction();
        try {
            $result = self::recordStatusChange($conn, $ctx, $taskId, $before, $newStatusId, $skipReason);
            if ($own) $conn->commit();
        } catch (Throwable $e) {
            if ($own && $conn->inTransaction()) $conn->rollBack();
            throw $e;
        }
        self::afterCommit($conn, $ctx, $result);
    }

    /**
     * THE status hook's EVIDENCE half (GH #181) - call INSIDE the transaction that writes the
     * status, after that write. Records the change; on completing, who did it and the due date in
     * force, the procedure texts (#190), and - for a repeat set to "after completion" - whether a
     * successor is now expected. Any failure throws, so the caller's transaction rolls the status
     * change back with it: the change and its record stand or fall together.
     *
     * @return ?array what afterCommit() needs (the successor to create), or null
     */
    public static function recordStatusChange(PDO $conn, ?ActorContext $ctx, int $taskId, array $before, int $newStatusId,
                                              ?string $skipReason = null): ?array
    {
        if (!$before || (int)($before['status_id'] ?? 0) === $newStatusId) return null;
        $strict = self::ready($conn);
        try {
            $st = $conn->prepare("SELECT name, is_closed FROM task_statuses WHERE id = ?");
            $st->execute([$newStatusId]);
            $new = $st->fetch(PDO::FETCH_ASSOC) ?: ['name' => null, 'is_closed' => 0];
        } catch (Throwable $e) {
            if ($strict) throw self::notRecorded('status', $e);
            return null;
        }
        $wasClosed = !empty($before['status_is_closed']);
        $nowClosed = !empty($new['is_closed']);
        $rid = !empty($before['recurrence_id']) ? (int)$before['recurrence_id'] : null;
        $successor = null;

        self::recordStrict($conn, $taskId, 'status_changed', $ctx, $before['status_name'] ?? null, $new['name'], [], $rid);

        if (!$wasClosed && $nowClosed) {
            [$aid] = self::actor($ctx);
            $detail = ['due_date' => $before['due_date'] ?? null, 'scheduled_date' => $before['scheduled_date'] ?? null];
            try {
                if ($strict) {
                    $conn->prepare($skipReason !== null
                        ? "UPDATE tasks SET skipped_datetime = UTC_TIMESTAMP(), completed_by_id = NULL WHERE id = ?"
                        : "UPDATE tasks SET completed_by_id = ?, skipped_datetime = NULL WHERE id = ?")
                         ->execute($skipReason !== null ? [$taskId] : [$aid, $taskId]);
                }
            } catch (Throwable $e) {
                throw self::notRecorded('completed_by', $e);
            }
            self::recordStrict($conn, $taskId, $skipReason !== null ? 'skipped' : 'completed', $ctx, null,
                               $skipReason !== null ? $skipReason : ($before['due_date'] ?? null), $detail, $rid);
            // GH #190: the procedure texts this occurrence was done against are evidence too.
            require_once __DIR__ . '/task_procedures.php';
            TaskProcedures::freeze($conn, $taskId, $strict);
            // Top-level occurrences only: a subtask is a step inside the work, never a repeat of it.
            // Whether a successor is now EXPECTED is recorded here, in the transaction;
            // making it is afterCommit()'s - Dr4inder: the expectation must be durable first.
            if (empty($before['parent_task_id'])) {
                require_once __DIR__ . '/task_recurrence.php';
                $successor = TaskRecurrence::successorExpectation($conn, $taskId, $ctx, $strict);
            }
        } elseif ($wasClosed && !$nowClosed) {
            self::recordStrict($conn, $taskId, 'reopened', $ctx, $before['completed_datetime'] ?? null, null, [
                'completed_datetime' => $before['completed_datetime'] ?? null,
                'completed_by_id'    => isset($before['completed_by_id']) ? (int)$before['completed_by_id'] ?: null : null,
                'was_skipped'        => !empty($before['skipped_datetime']),
            ], $rid);
            try {
                if ($strict) $conn->prepare("UPDATE tasks SET completed_by_id = NULL, skipped_datetime = NULL WHERE id = ?")->execute([$taskId]);
            } catch (Throwable $e) {
                throw self::notRecorded('reopened', $e);
            }
        }
        return ['task_id' => $taskId, 'successor' => $successor];
    }

    /**
     * THE status hook's second half - AFTER the commit: make the successor whose expectation
     * is already on the record. A failure here is logged, not raised: the completion stands,
     * and the evidence report shows the successor as Missing, naming the completion.
     *
     * @param ?array $result  what recordStatusChange() returned
     */
    public static function afterCommit(PDO $conn, ?ActorContext $ctx, ?array $result): void
    {
        if (!$result || empty($result['successor']['create'])) return;
        try {
            require_once __DIR__ . '/task_recurrence.php';
            TaskRecurrence::createSuccessor($conn, (int)$result['task_id'], $result['successor']);
        } catch (Throwable $e) {
            error_log('Task recurrence: successor not created for task ' . $result['task_id'] . ': ' . $e->getMessage());
        }
    }

    /**
     * Records a version of a repeat's rule.
     *
     * @param string $kind  baseline, created, changed, stopped, resumed or finished
     * @param ?array $rule  the task_recurrences row as it now stands; read when null
     * @param array $extra  merged into the stored rule JSON, e.g. ['cause' => 'end date reached']
     */
    public static function recordRuleVersion(PDO $conn, int $recurrenceId, string $kind, ?ActorContext $ctx,
                                             ?array $rule = null, array $extra = []): void
    {
        try {
            if ($rule === null) {
                $r = $conn->prepare("SELECT * FROM task_recurrences WHERE id = ?");
                $r->execute([$recurrenceId]);
                $rule = $r->fetch(PDO::FETCH_ASSOC);
                if (!$rule) return;
            }
            $m = $conn->prepare("SELECT t.id, t.title, t.tenant_id FROM tasks t
                                  WHERE t.recurrence_id = ? AND t.parent_task_id IS NULL
                                  ORDER BY t.id DESC LIMIT 1");
            $m->execute([$recurrenceId]);
            $latest = $m->fetch(PDO::FETCH_ASSOC) ?: null;
            $master = $conn->prepare("SELECT MIN(id) FROM tasks WHERE recurrence_id = ?");
            $master->execute([$recurrenceId]);
            $masterId = $master->fetchColumn();

            $keep = array_intersect_key($rule, array_flip(['mode', 'freq', 'interval_n', 'weekdays', 'month_mode', 'day_of_month',
                'nth', 'nth_weekday', 'month_of_year', 'ends_mode', 'ends_on', 'max_occurrences', 'occurrences_created',
                'next_due_date', 'is_active', 'copy_description', 'copy_subtasks', 'copy_assignee', 'copy_tags', 'copy_links',
                'copy_attachments']));
            [$aid, , $name] = self::actor($ctx);
            if ($aid !== null && $name === null) $name = self::analystName($conn, $aid);

            $n = $conn->prepare("SELECT COALESCE(MAX(version_no), 0) + 1 FROM task_recurrence_versions WHERE recurrence_id = ?");
            $n->execute([$recurrenceId]);
            $conn->prepare("INSERT INTO task_recurrence_versions (recurrence_id, version_no, change_kind, rule_json, is_active,
                                                                  title, master_task_id, tenant_id, analyst_id, actor_name, created_datetime)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())")
                 ->execute([$recurrenceId, (int)$n->fetchColumn(), $kind, json_encode($keep + $extra),
                            in_array($kind, ['stopped', 'finished'], true) ? 0 : (int)($rule['is_active'] ?? 1),
                            $latest['title'] ?? null, $masterId ? (int)$masterId : null,
                            isset($latest['tenant_id']) ? (int)$latest['tenant_id'] : null, $aid, $name]);
        } catch (Throwable $e) {
            error_log('[task history] could not record a rule version for series ' . $recurrenceId . ': ' . $e->getMessage());
        }
    }

    /**
     * Freezes an occurrence of a repeat that is about to be deleted: the task, its checklists with every step
     * (ticks, values, results, exception notes), the step history, its events and audit, comments, subtasks and
     * attachment references. Call BEFORE the delete; the record is owned by the series and outlives it.
     *
     * @param int $taskId  the occurrence being deleted (top level, with a recurrence_id)
     */
    public static function recordRemoval(PDO $conn, ?ActorContext $ctx, int $taskId, ?array $snap = null, bool $strict = false): void
    {
        if ($strict && !self::ready($conn)) return;
        try {
            $snap = $snap ?? self::snapshot($conn, $taskId, $strict);
            if (!$snap) return;
            $t = $snap['task'];
            [$aid, , $name] = self::actor($ctx);
            if ($aid !== null && $name === null) $name = self::analystName($conn, $aid);
            $conn->prepare("INSERT INTO task_removed_records (task_id, recurrence_id, previous_occurrence_id, tenant_id, title,
                                                              scheduled_date, due_date, removed_by_id, removed_by_name,
                                                              removed_datetime, snapshot_json)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?)")
                 ->execute([$taskId, $t['recurrence_id'] ?? null, $t['previous_occurrence_id'] ?? null, $t['tenant_id'] ?? null,
                            $t['title'] ?? null, $t['scheduled_date'] ?? null, $t['due_date'] ?? null, $aid, $name,
                            json_encode($snap, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR)]);
            if (self::$failNextWrite === 'removed_record') { self::$failNextWrite = null; throw new RuntimeException('injected failure (test)'); }
            if ($strict) {
                self::recordStrict($conn, $taskId, 'removed', $ctx, null, null, ['title' => $t['title'] ?? null],
                                   isset($t['recurrence_id']) ? (int)$t['recurrence_id'] : null);
            } else {
                self::record($conn, $taskId, 'removed', $ctx, null, null, ['title' => $t['title'] ?? null],
                             isset($t['recurrence_id']) ? (int)$t['recurrence_id'] : null);
            }
        } catch (ServiceError $e) {
            if ($strict) throw $e;
            error_log('[task history] could not record the removal of task ' . $taskId . ': ' . $e->getMessage());
        } catch (Throwable $e) {
            // Strict (deleteTask): the occurrence is NOT deleted without its retained record.
            if ($strict) throw self::notRecorded('removal', $e);
            error_log('[task history] could not record the removal of task ' . $taskId . ': ' . $e->getMessage());
        }
    }

    /**
     * Everything the evidence report reads about one task, as plain arrays.
     *
     * @param int $taskId  the task
     */
    public static function snapshot(PDO $conn, int $taskId, bool $strict = false): ?array
    {
        /* Strict (a removal about to happen): a failed READ is a failure, not an empty section -
           an occurrence deleted with "no comments" because the comments query broke is the very
           gap the retained record exists to close. A table that does not exist on this install
           (42S02) holds nothing to keep, so that alone reads as empty. */
        $q = function (string $sql, array $args) use ($conn, $strict): array {
            try { $s = $conn->prepare($sql); $s->execute($args); return $s->fetchAll(PDO::FETCH_ASSOC) ?: []; }
            catch (Throwable $e) {
                if ($strict && !($e instanceof PDOException && $e->getCode() === '42S02')) throw $e;
                return [];
            }
        };
        if ($strict && self::$failNextWrite === 'snapshot_read') { self::$failNextWrite = null; throw new RuntimeException('injected failure (test)'); }
        $task = $q("SELECT t.*, ts.name AS status_name, ts.is_closed AS status_is_closed
                      FROM tasks t LEFT JOIN task_statuses ts ON ts.id = t.status_id WHERE t.id = ?", [$taskId])[0] ?? null;
        if (!$task) return null;
        $lists = $q("SELECT * FROM task_checklists WHERE task_id = ? ORDER BY sort_order, id", [$taskId]);
        foreach ($lists as &$l) {
            $l['items'] = $q("SELECT * FROM task_checklist_items WHERE task_checklist_id = ? ORDER BY sort_order, id", [(int)$l['id']]);
        }
        unset($l);
        $docs = $q("SELECT d.id, d.kind, d.title, d.original_name, d.size_bytes, d.content_hash, d.external_url,
                           l.linked_by_id, l.created_datetime
                      FROM document_links l JOIN documents d ON d.id = l.document_id
                     WHERE l.parent_type = 'task' AND l.parent_id = ?", [$taskId]);
        return [
            'version'     => 1,
            'taken_utc'   => gmdate('Y-m-d H:i:s'),
            'task'        => $task,
            'checklists'  => $lists,
            'step_events' => $q("SELECT * FROM task_checklist_item_events WHERE task_id = ? ORDER BY id", [$taskId]),
            'events'      => $q("SELECT * FROM task_events WHERE task_id = ? ORDER BY id", [$taskId]),
            'audit'       => $q("SELECT * FROM task_audit WHERE task_id = ? ORDER BY id", [$taskId]),
            'comments'    => $q("SELECT c.id, c.analyst_id, a.full_name AS analyst_name, c.comment, c.created_datetime
                                   FROM task_comments c LEFT JOIN analysts a ON a.id = c.analyst_id
                                  WHERE c.task_id = ? ORDER BY c.id", [$taskId]),
            'subtasks'    => $q("SELECT t.id, t.title, ts.name AS status_name, t.completed_datetime
                                   FROM tasks t LEFT JOIN task_statuses ts ON ts.id = t.status_id
                                  WHERE t.parent_task_id = ? ORDER BY t.board_position, t.id", [$taskId]),
            'documents'   => $docs,
            // GH #190: its forms and every submission made for them, answers and labels included.
            'forms'       => (function () use ($conn, $taskId, $strict) { require_once __DIR__ . '/task_forms.php'; return TaskForms::snapshot($conn, $taskId, $strict); })(),
            // ...and the procedures it followed, with the frozen text each points at (GH #190 phase 2).
            'procedures'  => (function () use ($conn, $taskId, $strict) { require_once __DIR__ . '/task_procedures.php'; return TaskProcedures::snapshot($conn, $taskId, $strict); })(),
            // ...and its follow-up tickets and tasks (GH #190 phase 3).
            'follow_ups'  => (function () use ($conn, $taskId, $strict) { require_once __DIR__ . '/task_follow_ups.php'; return TaskFollowUps::snapshot($conn, $taskId, $strict); })(),
        ];
    }

    /**
     * The task's history for the History tab, newest first: its events, the older task_audit rows
     * (company moves, checklist overrides, calendar sync) and its checklist step changes, merged.
     *
     * @param int $taskId  the task
     * @param bool $strict  false (the History tab): a source that cannot be read is left out. true (the REST
     *     API): only a table Database Verification hasn't created yet is left out - any other error is thrown,
     *     so a failed read is never answered as "no history".
     * @param bool $steps  false leaves out the checklist step changes, for a reader who may not see checklists
     * @return array<int,array{at:string,kind:string,type:string,who:?string,actor_kind:string,from:?string,to:?string,detail:array}>
     */
    public static function forTask(PDO $conn, int $taskId, bool $strict = false, bool $steps = true): array
    {
        $out = [];
        try {
            $s = $conn->prepare("SELECT e.*, a.full_name FROM task_events e LEFT JOIN analysts a ON a.id = e.analyst_id
                                  WHERE e.task_id = ? ORDER BY e.id DESC LIMIT 500");
            $s->execute([$taskId]);
            foreach ($s->fetchAll(PDO::FETCH_ASSOC) as $r) {
                $out[] = ['at' => $r['created_datetime'], 'kind' => 'event', 'type' => $r['event_type'],
                          'who' => $r['actor_name'] ?: $r['full_name'], 'actor_kind' => $r['actor_kind'],
                          'from' => $r['from_value'], 'to' => $r['to_value'],
                          'detail' => $r['detail_json'] ? (json_decode($r['detail_json'], true) ?: []) : [],
                          'job_run_id' => $r['job_run_id'] !== null ? (int)$r['job_run_id'] : null];
            }
        } catch (Throwable $e) { self::readFailed($e, $strict); /* before Database Verification */ }
        try {
            $s = $conn->prepare("SELECT au.*, a.full_name FROM task_audit au LEFT JOIN analysts a ON a.id = au.analyst_id
                                  WHERE au.task_id = ? ORDER BY au.id DESC LIMIT 500");
            $s->execute([$taskId]);
            foreach ($s->fetchAll(PDO::FETCH_ASSOC) as $r) {
                $out[] = ['at' => $r['created_datetime'], 'kind' => 'audit', 'type' => $r['field_name'],
                          'who' => $r['full_name'], 'actor_kind' => $r['analyst_id'] ? 'analyst' : ($r['source'] ?: 'system'),
                          'from' => $r['old_value'], 'to' => $r['new_value'], 'detail' => ['source' => $r['source']]];
            }
        } catch (Throwable $e) { self::readFailed($e, $strict); }
        if ($steps) try {
            $s = $conn->prepare("SELECT * FROM task_checklist_item_events WHERE task_id = ? ORDER BY id DESC LIMIT 500");
            $s->execute([$taskId]);
            foreach ($s->fetchAll(PDO::FETCH_ASSOC) as $r) {
                $out[] = ['at' => $r['created_datetime'], 'kind' => 'step', 'type' => $r['action'],
                          'who' => $r['actor_name'], 'actor_kind' => $r['analyst_id'] ? 'analyst' : 'system',
                          'from' => null, 'to' => null,
                          'detail' => ['checklist' => $r['checklist_title'], 'step' => $r['item_title'],
                                       'before' => json_decode((string)$r['before_json'], true) ?: [],
                                       'after' => json_decode((string)$r['after_json'], true) ?: [],
                                       'after_completion' => (bool)$r['after_completion']]];
            }
        } catch (Throwable $e) { self::readFailed($e, $strict); }
        usort($out, fn($a, $b) => strcmp((string)$b['at'], (string)$a['at']));
        return $out;
    }

    /**
     * A history source could not be read. Not strict: leave it out, as the History tab always has.
     * Strict: only a missing table (before Database Verification) is left out; anything else is thrown.
     */
    private static function readFailed(Throwable $e, bool $strict): void
    {
        if (!$strict) return;
        require_once __DIR__ . '/../db_errors.php';
        if ($e instanceof PDOException && dbErrorIsMissingTable($e)) return;
        throw $e;
    }

    /** An analyst's display name, or null. */
    private static function analystName(PDO $conn, int $id): ?string
    {
        static $cache = [];
        if (array_key_exists($id, $cache)) return $cache[$id];
        try {
            $s = $conn->prepare("SELECT full_name FROM analysts WHERE id = ?");
            $s->execute([$id]);
            $v = $s->fetchColumn();
            return $cache[$id] = ($v !== false && $v !== null && $v !== '') ? (string)$v : null;
        } catch (Throwable) {
            return null;
        }
    }
}
