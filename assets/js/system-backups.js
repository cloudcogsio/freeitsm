/**
 * System -> Backups (#286). Talks to api/system/backups.php (window.BK_API).
 */
(function () {
    'use strict';
    var t = function (k, p) { return window.t('system.backups.' + k, p); };
    var $ = function (id) { return document.getElementById(id); };
    var state = { settings: null, runs: null, verifyRun: null, restoreRun: null, polling: null };

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function msg(id, text, ok) {
        var el = $(id);
        el.textContent = text || '';
        el.className = 'bk-msg' + (text ? (ok ? ' ok' : ' err') : '');
    }
    function mb(bytes) { return bytes == null ? '' : t('size_mb', { n: (bytes / 1048576).toFixed(1) }); }
    function when(v) { return v ? (window.fmtDateTime ? window.fmtDateTime(v) : v) : ''; }

    async function api(body) {
        var opts = body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {};
        var resp = await fetch(window.BK_API, opts);
        var data;
        try { data = await resp.json(); } catch (e) { data = { success: false, error: t('err_server') }; }
        return data;
    }

    function targetInput() {
        var type = document.querySelector('input[name="bkType"]:checked').value;
        if (type === 'folder') return { type: 'folder', folder: $('bkFolder').value.trim() };
        return { type: 's3', s3: {
            endpoint: $('bkEndpoint').value.trim(), region: $('bkRegion').value.trim(), bucket: $('bkBucket').value.trim(),
            prefix: $('bkPrefix').value.trim(), access_key_id: $('bkKeyId').value.trim(), secret: $('bkSecret').value,
            path_style: $('bkPathStyle').checked
        } };
    }

    function showType() {
        var s3 = document.querySelector('input[name="bkType"]:checked').value === 's3';
        $('bkS3Fields').classList.toggle('bk-hidden', !s3);
        $('bkFolderFields').classList.toggle('bk-hidden', s3);
    }
    function showMode() {
        var m = $('bkMode').value;
        $('bkWeekdayWrap').classList.toggle('bk-hidden', m !== 'weekly');
        $('bkTimeWrap').classList.toggle('bk-hidden', m === 'off');
    }

    function render() {
        var s = state.settings;
        if (s.target) {
            document.querySelector('input[name="bkType"][value="' + s.target.type + '"]').checked = true;
            if (s.target.type === 'folder') {
                $('bkFolder').value = s.target.folder;
            } else {
                $('bkEndpoint').value = s.target.s3.endpoint; $('bkRegion').value = s.target.s3.region;
                $('bkBucket').value = s.target.s3.bucket; $('bkPrefix').value = s.target.s3.prefix;
                $('bkKeyId').value = s.target.s3.access_key_id; $('bkSecret').value = s.target.s3.secret;
                $('bkPathStyle').checked = !!s.target.s3.path_style;
            }
        }
        showType();
        $('bkPassStatus').textContent = s.has_passphrase ? t('pass_is_set') : t('pass_not_set');
        $('bkPassCurrentWrap').classList.toggle('bk-hidden', !s.has_passphrase);
        $('bkPassBtn').textContent = s.has_passphrase ? t('pass_change') : t('pass_set');
        $('bkMode').value = s.schedule.mode;
        if (s.schedule.weekday) $('bkWeekday').value = String(s.schedule.weekday);
        if (s.schedule.time) $('bkTime').value = s.schedule.time;
        $('bkKeep').value = s.keep;
        showMode();
        var why = !s.sodium ? t('err_sodium') : !s.target ? t('now_needs_target') : !s.has_passphrase ? t('now_needs_passphrase') : s.running ? t('now_running') : '';
        $('bkNowBtn').disabled = why !== '';
        if (why) msg('bkNowMsg', why, s.running); else if ($('bkNowMsg').textContent === t('now_running')) msg('bkNowMsg', '');
        renderLastRestore();
        renderRuns();
    }

    function renderRuns() {
        var tb = $('bkRuns');
        if (state.runs === null) {
            tb.innerHTML = '<tr><td colspan="7">' + esc(t('runs_unknown')) + '</td></tr>';
            return;
        }
        if (!state.runs.length) {
            tb.innerHTML = '<tr><td colspan="7">' + esc(t('runs_none')) + '</td></tr>';
            return;
        }
        tb.innerHTML = state.runs.map(function (r) {
            var detail = r.status === 'failed' ? r.error_text : r.warning_text;
            var verified = r.verify_status
                ? '<span class="bk-pill ' + esc(r.verify_status) + '">' + esc(t('status_' + r.verify_status)) + '</span> ' + esc(when(r.verified_at))
                  + (r.verify_detail && r.verify_status === 'failed' ? '<div class="bk-detail">' + esc(r.verify_detail) + '</div>' : '')
                : '';
            return '<tr>'
                + '<td>' + esc(when(r.started_at)) + (r.started_by_name ? '<div class="bk-detail">' + esc(r.started_by_name) + '</div>' : '') + '</td>'
                + '<td>' + esc(t('kind_' + r.kind)) + '</td>'
                + '<td><span class="bk-pill ' + esc(r.status) + '">' + esc(t('status_' + r.status)) + '</span>'
                + (detail ? '<div class="bk-detail">' + esc(detail) + '</div>' : '') + '</td>'
                + '<td>' + esc(mb(r.size_bytes)) + '</td>'
                + '<td>' + (r.files_total != null ? esc(t('files_line', { total: r.files_total, n: r.files_new })) : '') + '</td>'
                + '<td>' + verified + '</td>'
                + '<td class="bk-row-actions">' + (r.status === 'ok' && r.kind !== 'restore' && r.verify_status !== 'running'
                    ? '<button class="btn" type="button" data-verify="' + esc(r.id) + '" data-set="' + esc(r.set_name) + '">' + esc(t('verify')) + '</button>'
                      + '<button class="btn" type="button" data-restore="' + esc(r.id) + '" data-set="' + esc(r.set_name) + '">' + esc(t('restore')) + '</button>' : '')
                + '</td></tr>';
        }).join('');
    }

    function renderLastRestore() {
        var l = state.settings.last_restore, el = $('bkLastRestore');
        var text = !l ? '' : l.state === 'done' ? t('restore_last_done', { set: l.set, when: when(l.ended_at), safety: l.safety_set || '' })
                 : l.state === 'failed' ? t('restore_last_failed', { set: l.set, when: when(l.ended_at), error: l.error || '' })
                 : l.state === 'abandoned' ? t('restore_last_abandoned', { set: l.set, when: when(l.ended_at) }) : '';
        el.textContent = text;
        el.className = text ? 'bk-msg ' + (l.state === 'done' ? 'ok' : 'err') : 'bk-hidden';
    }

    function openRestore(runId, set) {
        state.restoreRun = runId;
        $('bkVerifyBox').classList.add('bk-hidden');
        $('bkRestoreHeading').textContent = t('restore_heading', { set: set });
        $('bkRestorePass').value = '';
        $('bkRestoreConfirm').value = '';
        $('bkRestoreGo').disabled = true;
        $('bkRestoreStep2').classList.add('bk-hidden');
        $('bkRestoreCheck').disabled = false;
        msg('bkRestoreMsg', '');
        $('bkRestoreBox').classList.remove('bk-hidden');
        $('bkRestorePass').focus();
    }

    function closeRestore() {
        $('bkRestorePass').value = '';
        $('bkRestoreBox').classList.add('bk-hidden');
    }

    async function load() {
        var d = await api();
        $('bkLoading').classList.add('bk-hidden');
        if (!d.success) {
            $('bkMissing').textContent = d.error || t('err_server');
            $('bkMissing').classList.remove('bk-hidden');
            return;
        }
        state.settings = d.settings;
        state.runs = d.runs;
        if (d.runs === null) {
            $('bkMissing').textContent = t('runs_unknown');
            $('bkMissing').classList.remove('bk-hidden');
        }
        $('bkContent').classList.remove('bk-hidden');
        render();
        var busy = d.settings.running || (d.runs || []).some(function (r) { return r.status === 'running' || r.verify_status === 'running'; });
        clearTimeout(state.polling);
        if (busy) state.polling = setTimeout(load, 5000);
    }

    async function run(btn, msgId, body, okText, then) {
        btn.disabled = true;
        msg(msgId, t('working'), true);
        try {
            var d = await api(body);
            if (d.success) { msg(msgId, okText, true); if (then) await then(d); }
            else msg(msgId, d.error || t('err_server'), false);
        } catch (e) {
            msg(msgId, t('err_server'), false);
        } finally {
            btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('input[name="bkType"]').forEach(function (r) { r.addEventListener('change', showType); });
        $('bkMode').addEventListener('change', showMode);

        $('bkTestBtn').addEventListener('click', function () {
            var btn = this;
            btn.disabled = true;
            msg('bkTargetMsg', t('working'), true);
            api({ action: 'test', target: targetInput() }).then(function (d) {
                if (!d.success) { msg('bkTargetMsg', d.error || t('err_server'), false); return; }
                if (d.test.ok) msg('bkTargetMsg', t('test_ok'), true);
                else msg('bkTargetMsg', t('test_failed', { step: t('step_' + d.test.step), error: d.test.error || '' }), false);
            }).finally(function () { btn.disabled = false; });
        });
        $('bkSaveTargetBtn').addEventListener('click', function () {
            run(this, 'bkTargetMsg', { action: 'save_target', target: targetInput() }, t('saved'), load);
        });
        $('bkPassBtn').addEventListener('click', function () {
            var change = state.settings && state.settings.has_passphrase;
            var body = change
                ? { action: 'change_passphrase', current: $('bkPassCurrent').value, passphrase: $('bkPassNew').value, confirm: $('bkPassConfirm').value }
                : { action: 'set_passphrase', passphrase: $('bkPassNew').value, confirm: $('bkPassConfirm').value };
            run(this, 'bkPassMsg', body, change ? t('pass_changed') : t('pass_saved'), function () {
                $('bkPassCurrent').value = ''; $('bkPassNew').value = ''; $('bkPassConfirm').value = '';
                return load();
            });
        });
        $('bkScheduleBtn').addEventListener('click', function () {
            run(this, 'bkScheduleMsg', { action: 'save_schedule', mode: $('bkMode').value, weekday: $('bkWeekday').value,
                                         time: $('bkTime').value, keep: parseInt($('bkKeep').value, 10) || 0 }, t('saved'), load);
        });
        $('bkNowBtn').addEventListener('click', function () {
            run(this, 'bkNowMsg', { action: 'backup_now' }, t('now_started'), function () {
                state.settings.running = true;
                setTimeout(load, 2000);
            });
        });
        $('bkRuns').addEventListener('click', function (e) {
            var r = e.target.closest('button[data-restore]');
            if (r) { openRestore(parseInt(r.getAttribute('data-restore'), 10), r.getAttribute('data-set')); return; }
            var b = e.target.closest('button[data-verify]');
            if (!b) return;
            closeRestore();
            state.verifyRun = parseInt(b.getAttribute('data-verify'), 10);
            $('bkVerifyLabel').textContent = t('verify_prompt', { set: b.getAttribute('data-set') });
            $('bkVerifyPass').value = '';
            msg('bkVerifyMsg', '');
            $('bkVerifyBox').classList.remove('bk-hidden');
            $('bkVerifyPass').focus();
        });
        $('bkVerifyCancel').addEventListener('click', function () { $('bkVerifyBox').classList.add('bk-hidden'); });
        $('bkVerifyGo').addEventListener('click', function () {
            var pass = $('bkVerifyPass').value;
            setTimeout(load, 1500);   // show "running" while it works
            run(this, 'bkVerifyMsg', { action: 'verify', run_id: state.verifyRun, passphrase: pass }, '', function (d) {
                $('bkVerifyPass').value = '';
                msg('bkVerifyMsg', d.verify.ok ? t('verify_ok', { n: d.verify.checked }) : t('verify_failed'), d.verify.ok);
                return load();
            });
        });
        $('bkRestoreCancel').addEventListener('click', closeRestore);
        $('bkRestoreCancel2').addEventListener('click', closeRestore);
        $('bkRestoreCheck').addEventListener('click', function () {
            run(this, 'bkRestoreMsg', { action: 'restore_check', run_id: state.restoreRun, passphrase: $('bkRestorePass').value }, '', function (d) {
                var r = d.restore;
                msg('bkRestoreMsg', '');
                $('bkRestoreInfo').textContent = t('restore_info', { when: when(r.created_at), version: r.app_version || '?', files: r.files, size: mb(r.size) });
                $('bkRestoreKeyWarn').classList.toggle('bk-hidden', !r.key_differs);
                $('bkRestoreConfirmLabel').textContent = t('restore_confirm_label', { word: state.settings.restore_confirm });
                $('bkRestoreStep2').classList.remove('bk-hidden');
                $('bkRestoreCheck').disabled = true;
                $('bkRestoreConfirm').focus();
            }).then(function () { if (!$('bkRestoreStep2').classList.contains('bk-hidden')) $('bkRestoreCheck').disabled = true; });
        });
        $('bkRestoreConfirm').addEventListener('input', function () {
            $('bkRestoreGo').disabled = this.value !== state.settings.restore_confirm;
        });
        $('bkRestoreGo').addEventListener('click', function () {
            var btn = this;
            run(btn, 'bkRestoreMsg', { action: 'restore_start', run_id: state.restoreRun, passphrase: $('bkRestorePass').value, confirm: $('bkRestoreConfirm').value },
                t('restore_starting'), function () {
                    $('bkRestorePass').value = '';
                    btn.disabled = true;
                    // From now on every page is the maintenance page; this browser's is the progress page.
                    setTimeout(function () { window.location.reload(); }, 800);
                });
        });
        load();
    });
})();
