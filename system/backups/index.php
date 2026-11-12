<?php
/**
 * System - Backups (#286): where backups go, the passphrase that protects them, when
 * they run, and every run with its result. Restoring is done from the command line
 * (scripts/backup_restore.php); see the help page.
 */
session_start();
require_once '../../config.php';
require_once '../../includes/i18n.php';
require_once '../../includes/timezone.php';
require_once '../../includes/theme.php';
I18n::initFromSession();
Tz::init();

$current_page = 'backups';
require_once __DIR__ . '/../includes/page_gate.php';
$path_prefix = '../../';
$translationNamespaces = ['common', 'system'];
$h = fn(string $k, array $p = []) => htmlspecialchars(t($k, $p));
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(I18n::getLocale()); ?>" data-theme="<?php echo htmlspecialchars(Theme::active()); ?>" data-theme-mode="<?php echo htmlspecialchars(Theme::mode()); ?>">
<head>
    <link rel="icon" type="image/svg+xml" href="<?php echo defined('BASE_URL') ? BASE_URL : '/'; ?>favicon.svg">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(pageTitle('system', t('system.backups.title'))); ?></title>
    <link rel="stylesheet" href="../../assets/css/theme.css?v=27">
    <link rel="stylesheet" href="../../assets/css/inbox.css?v=79">
    <style>
        body { --accent: var(--sys-accent, #546e7a); --accent-hover: var(--sys-accent-hover, #37474f); --on-accent: var(--sys-on-accent, #fff); }
        .main-container { flex: 1; background: var(--app-bg, #f5f7fa); overflow-y: auto; }
        .bk-container { max-width: 960px; margin: 0 auto; padding: 30px 20px; }
        .page-title { font-size: 22px; font-weight: 600; color: var(--text, #333); margin: 0 0 6px 0; }
        .page-subtitle { font-size: 13px; color: var(--text-dim, #888); margin: 0 0 24px 0; }
        .bk-card { background: var(--surface, #fff); border: 1px solid var(--border, #e0e0e0); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .bk-card h3 { margin: 0 0 4px 0; font-size: 16px; color: var(--text, #333); }
        .bk-card .bk-hint { margin: 0 0 14px 0; font-size: 13px; color: var(--text-dim, #777); }
        .bk-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }
        .bk-field { display: flex; flex-direction: column; gap: 4px; min-width: 200px; flex: 1; }
        .bk-field label { font-size: 12px; font-weight: 600; color: var(--text-dim, #666); }
        .bk-field input, .bk-field select { padding: 8px 10px; border: 1px solid var(--border, #ccc); border-radius: 5px; font-size: 14px;
                                            background: var(--input-bg, #fff); color: var(--text, #333); }
        .bk-check { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text, #333); }
        .bk-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .btn { padding: 8px 16px; border-radius: 5px; border: 1px solid var(--border, #ccc); background: var(--surface, #fff); color: var(--text, #333); cursor: pointer; font-size: 14px; }
        .btn:disabled { opacity: .55; cursor: default; }
        .btn-primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
        .btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
        .bk-msg { font-size: 13px; }
        .bk-msg.ok { color: var(--success, #2e7d32); }
        .bk-msg.err { color: var(--danger, #c62828); white-space: pre-line; }
        .bk-warning { background: var(--warn-bg, #fff8e1); border: 1px solid var(--warn-border, #ffe082); color: var(--text, #5d4037);
                      border-radius: 6px; padding: 10px 12px; font-size: 13px; margin-bottom: 14px; }
        .bk-status { font-size: 13px; color: var(--text, #333); margin-bottom: 12px; }
        .bk-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .bk-table th, .bk-table td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--border, #eee); vertical-align: top; }
        .bk-table th { color: var(--text-dim, #666); font-weight: 600; }
        .bk-pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; background: var(--chip-bg, #eceff1); }
        .bk-pill.ok { background: #e8f5e9; color: #2e7d32; }
        .bk-pill.failed { background: #ffebee; color: #c62828; }
        .bk-pill.running { background: #e3f2fd; color: #1565c0; }
        [data-theme-mode="dark"] .bk-pill.ok { background: #1b3a1e; color: #a5d6a7; }
        [data-theme-mode="dark"] .bk-pill.failed { background: #4a1c1c; color: #ef9a9a; }
        [data-theme-mode="dark"] .bk-pill.running { background: #0d2a45; color: #90caf9; }
        [data-theme-mode="dark"] .bk-warning { background: #3a3220; border-color: #6d5a2a; color: var(--text); }
        .bk-detail { color: var(--text-dim, #777); font-size: 12px; white-space: pre-line; margin-top: 4px; }
        .bk-hidden { display: none !important; }
    </style>
    <link rel="stylesheet" href="../../assets/css/mobile.css?v=196">
</head>
<body data-mobile-module="system" data-mobile-page="backups">
    <?php include '../includes/header.php'; ?>

    <div class="main-container">
        <div class="bk-container">
            <h1 class="page-title"><?php echo $h('system.backups.title'); ?></h1>
            <p class="page-subtitle"><?php echo $h('system.backups.subtitle'); ?></p>

            <div id="bkLoading"><?php echo $h('system.backups.loading'); ?></div>
            <div id="bkMissing" class="bk-warning bk-hidden"></div>

            <div id="bkContent" class="bk-hidden">
                <!-- 1. Target -->
                <div class="bk-card">
                    <h3><?php echo $h('system.backups.target_heading'); ?></h3>
                    <p class="bk-hint"><?php echo $h('system.backups.target_hint'); ?></p>
                    <div class="bk-row">
                        <label class="bk-check"><input type="radio" name="bkType" value="folder" checked> <?php echo $h('system.backups.target_folder'); ?></label>
                        <label class="bk-check"><input type="radio" name="bkType" value="s3"> <?php echo $h('system.backups.target_s3'); ?></label>
                    </div>
                    <div id="bkFolderFields" class="bk-row">
                        <div class="bk-field"><label for="bkFolder"><?php echo $h('system.backups.folder'); ?></label>
                            <input id="bkFolder" type="text" placeholder="/mnt/backups/freeitsm" autocomplete="off"></div>
                    </div>
                    <div id="bkS3Fields" class="bk-hidden">
                        <div class="bk-row">
                            <div class="bk-field"><label for="bkEndpoint"><?php echo $h('system.backups.s3_endpoint'); ?></label><input id="bkEndpoint" type="text" placeholder="https://s3.example.com" autocomplete="off"></div>
                            <div class="bk-field"><label for="bkRegion"><?php echo $h('system.backups.s3_region'); ?></label><input id="bkRegion" type="text" placeholder="us-east-1" autocomplete="off"></div>
                        </div>
                        <div class="bk-row">
                            <div class="bk-field"><label for="bkBucket"><?php echo $h('system.backups.s3_bucket'); ?></label><input id="bkBucket" type="text" autocomplete="off"></div>
                            <div class="bk-field"><label for="bkPrefix"><?php echo $h('system.backups.s3_prefix'); ?></label><input id="bkPrefix" type="text" autocomplete="off"></div>
                        </div>
                        <div class="bk-row">
                            <div class="bk-field"><label for="bkKeyId"><?php echo $h('system.backups.s3_key'); ?></label><input id="bkKeyId" type="text" autocomplete="off"></div>
                            <div class="bk-field"><label for="bkSecret"><?php echo $h('system.backups.s3_secret'); ?></label><input id="bkSecret" type="password" autocomplete="new-password"></div>
                        </div>
                        <div class="bk-row"><label class="bk-check"><input id="bkPathStyle" type="checkbox"> <?php echo $h('system.backups.s3_path_style'); ?></label></div>
                    </div>
                    <div class="bk-actions">
                        <button class="btn" id="bkTestBtn" type="button"><?php echo $h('system.backups.test'); ?></button>
                        <button class="btn btn-primary" id="bkSaveTargetBtn" type="button"><?php echo $h('common.save'); ?></button>
                        <span class="bk-msg" id="bkTargetMsg"></span>
                    </div>
                </div>

                <!-- 2. Passphrase -->
                <div class="bk-card">
                    <h3><?php echo $h('system.backups.pass_heading'); ?></h3>
                    <div class="bk-warning"><?php echo $h('system.backups.pass_warning'); ?></div>
                    <div id="bkPassStatus" class="bk-status"></div>
                    <div class="bk-row">
                        <div class="bk-field bk-hidden" id="bkPassCurrentWrap"><label for="bkPassCurrent"><?php echo $h('system.backups.pass_current'); ?></label><input id="bkPassCurrent" type="password" autocomplete="off"></div>
                        <div class="bk-field"><label for="bkPassNew"><?php echo $h('system.backups.pass_new'); ?></label><input id="bkPassNew" type="password" autocomplete="new-password"></div>
                        <div class="bk-field"><label for="bkPassConfirm"><?php echo $h('system.backups.pass_confirm'); ?></label><input id="bkPassConfirm" type="password" autocomplete="new-password"></div>
                    </div>
                    <div class="bk-actions">
                        <button class="btn btn-primary" id="bkPassBtn" type="button"><?php echo $h('system.backups.pass_set'); ?></button>
                        <span class="bk-msg" id="bkPassMsg"></span>
                    </div>
                </div>

                <!-- 3. Schedule -->
                <div class="bk-card">
                    <h3><?php echo $h('system.backups.schedule_heading'); ?></h3>
                    <p class="bk-hint"><?php echo $h('system.backups.schedule_hint'); ?></p>
                    <div class="bk-row">
                        <div class="bk-field"><label for="bkMode"><?php echo $h('system.backups.schedule_label'); ?></label>
                            <select id="bkMode">
                                <option value="off"><?php echo $h('system.backups.schedule_off'); ?></option>
                                <option value="daily"><?php echo $h('system.backups.schedule_daily'); ?></option>
                                <option value="weekly"><?php echo $h('system.backups.schedule_weekly'); ?></option>
                            </select></div>
                        <div class="bk-field" id="bkWeekdayWrap"><label for="bkWeekday"><?php echo $h('system.backups.schedule_day'); ?></label>
                            <select id="bkWeekday">
                                <?php foreach ([1 => 'mon', 2 => 'tue', 3 => 'wed', 4 => 'thu', 5 => 'fri', 6 => 'sat', 7 => 'sun'] as $n => $d): ?>
                                    <option value="<?php echo $n; ?>"><?php echo $h('system.backups.day_' . $d); ?></option>
                                <?php endforeach; ?>
                            </select></div>
                        <div class="bk-field" id="bkTimeWrap"><label for="bkTime"><?php echo $h('system.backups.schedule_time'); ?></label><input id="bkTime" type="time" value="02:00"></div>
                        <div class="bk-field"><label for="bkKeep"><?php echo $h('system.backups.keep'); ?></label><input id="bkKeep" type="number" min="1" max="365" value="7"></div>
                    </div>
                    <div class="bk-actions">
                        <button class="btn btn-primary" id="bkScheduleBtn" type="button"><?php echo $h('common.save'); ?></button>
                        <span class="bk-msg" id="bkScheduleMsg"></span>
                    </div>
                </div>

                <!-- 4. Back up now + history -->
                <div class="bk-card">
                    <h3><?php echo $h('system.backups.history_heading'); ?></h3>
                    <div class="bk-actions" style="margin-bottom: 14px;">
                        <button class="btn btn-primary" id="bkNowBtn" type="button"><?php echo $h('system.backups.now'); ?></button>
                        <span class="bk-msg" id="bkNowMsg"></span>
                    </div>
                    <div id="bkVerifyBox" class="bk-row bk-hidden">
                        <div class="bk-field"><label for="bkVerifyPass" id="bkVerifyLabel"></label><input id="bkVerifyPass" type="password" autocomplete="off"></div>
                        <div class="bk-actions" style="align-self: flex-end;">
                            <button class="btn btn-primary" id="bkVerifyGo" type="button"><?php echo $h('system.backups.verify'); ?></button>
                            <button class="btn" id="bkVerifyCancel" type="button"><?php echo $h('common.cancel'); ?></button>
                            <span class="bk-msg" id="bkVerifyMsg"></span>
                        </div>
                    </div>
                    <table class="bk-table">
                        <thead><tr>
                            <th><?php echo $h('system.backups.col_started'); ?></th>
                            <th><?php echo $h('system.backups.col_type'); ?></th>
                            <th><?php echo $h('system.backups.col_status'); ?></th>
                            <th><?php echo $h('system.backups.col_size'); ?></th>
                            <th><?php echo $h('system.backups.col_files'); ?></th>
                            <th><?php echo $h('system.backups.col_verified'); ?></th>
                            <th></th>
                        </tr></thead>
                        <tbody id="bkRuns"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>window.translations = <?php echo json_encode(I18n::exportForJs($translationNamespaces), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE); ?>;</script>
    <script>window.BK_API = '<?php echo $path_prefix; ?>api/system/backups.php';</script>
    <script src="../../assets/js/tz.js?v=5"></script>
    <script src="../../assets/js/i18n.js?v=3"></script>
    <script src="../../assets/js/system-backups.js?v=1"></script>
    <script src="../../assets/js/mobile.js?v=83"></script>
</body>
</html>
