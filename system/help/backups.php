<?php
/**
 * System Help — Backups.
 */
require __DIR__ . '/_init.php';
$helpSlug = 'backups';
require __DIR__ . '/_top.php';
?>
<!-- 1. What is backed up -->
<div class="help-section" id="overview">
    <div class="help-section-header"><?php echo helpSectionNum('overview'); ?>
        <div>
            <h3>What is backed up</h3>
            <p>Everything FreeITSM needs to come back after the server is lost, in one backup:</p>
        </div>
    </div>
    <ul>
        <li><strong>The database</strong>, every table, taken at a single moment so it is consistent. All settings are in it.</li>
        <li><strong>Every stored file</strong>: ticket and change attachments, documents, everything in Files (wherever Files keeps them, including S3-compatible storage), recordings, course content, RFP uploads, branding, label fonts, form images and war room files.</li>
        <li><strong>The encryption key</strong>, without which the passwords and API keys in the database cannot be read.</li>
    </ul>
    <p>Temporary files (uploads in progress, asset import files, recordings not yet attached to a ticket) and Files offline copies are left out; they are not needed to restore.</p>
    <p>Files are stored once: a file already in an earlier backup is not uploaded again, so after the first backup each one only sends what is new. Every backup still holds everything.</p>
</div>

<!-- 2. Target -->
<div class="help-section" id="target">
    <div class="help-section-header"><?php echo helpSectionNum('target'); ?>
        <div>
            <h3>Where backups go</h3>
        </div>
    </div>
    <p>Choose a <strong>folder on the server</strong> (best a mounted NAS or a second disk) or an <strong>S3-compatible bucket</strong> (Amazon S3, Backblaze B2, Wasabi, Cloudflare R2, MinIO and others). The bucket has its own settings, separate from Files storage, so backups can live somewhere else entirely - which is the point of a backup.</p>
    <p><strong>Test</strong> writes a small file, reads it back, lists it and deletes it. A location must pass before it can be saved. A folder inside FreeITSM itself is refused.</p>
    <div class="help-note">Changing the location does not move existing backups: they stay where they are and can still be restored from there with the command below.</div>
</div>

<!-- 3. Passphrase -->
<div class="help-section" id="passphrase">
    <div class="help-section-header"><?php echo helpSectionNum('passphrase'); ?>
        <div>
            <h3>The passphrase</h3>
        </div>
    </div>
    <p>Everything in a backup is encrypted. Someone who can read the bucket or folder sees only how many objects there are and their sizes - no names, no contents.</p>
    <p>The passphrase you set unlocks the backups. FreeITSM does <strong>not</strong> store it: scheduled backups only need a public key, so they run unattended, while restoring and verifying ask for the passphrase. Changing it later keeps every existing backup readable with the new one.</p>
    <div class="help-note warn"><strong>Losing the passphrase loses every backup.</strong> Nobody can recover it. Keep it in a password manager or a safe, away from this server.</div>
</div>

<!-- 4. Schedule -->
<div class="help-section" id="schedule">
    <div class="help-section-header"><?php echo helpSectionNum('schedule'); ?>
        <div>
            <h3>Schedule &amp; retention</h3>
        </div>
    </div>
    <p>Backups run every day or every week at the time you choose, in this install's time zone, as the background job <em>Backups</em> (System &rarr; Background jobs shows each run). <strong>Back up now</strong> starts one at once. The first backup of a large install can take hours; it carries on until it is done, and if it is interrupted the next one picks up where it stopped.</p>
    <p>After each successful backup, the oldest ones beyond the number you keep are removed, along with stored files no remaining backup needs. A backup that fails is listed with the reason, and every active administrator is emailed.</p>
</div>

<!-- 5. Verify -->
<div class="help-section" id="verify">
    <div class="help-section-header"><?php echo helpSectionNum('verify'); ?>
        <div>
            <h3>Verifying a backup</h3>
        </div>
    </div>
    <p>Every backup checks, before it is marked OK, that everything it refers to is on the target at the right size. <strong>Verify</strong> goes further: with the passphrase, it decrypts the whole backup and checks every file against its checksum, without changing anything. The result is shown on the backup's row. Doing this now and then proves the backups can actually be restored.</p>
</div>

<!-- 6. Restore -->
<div class="help-section" id="restore">
    <div class="help-section-header"><?php echo helpSectionNum('restore'); ?>
        <div>
            <h3>Restoring</h3>
        </div>
    </div>
    <h4>Putting this install back to a backup</h4>
    <p>Press <strong>Restore</strong> on a backup's row, enter the passphrase, check what the backup is, and type <code>RESTORE</code>. It is a true rollback of the whole install: the database, every uploaded file and everything in Files go back to how they were when the backup was made. Everything since is replaced, and files added since are deleted.</p>
    <ol>
        <li>FreeITSM goes into <strong>maintenance mode</strong>: everyone else sees a maintenance page, the API answers 503, and no background job starts. Your browser shows the progress.</li>
        <li>It waits for background jobs that are already running to finish, then takes a <strong>safety backup</strong> of the current state, so the restore can itself be undone (restore the safety backup the same way).</li>
        <li>It restores the backup into the current storage, deletes what the backup does not hold (including stored Files content that no file in Files refers to), and runs Database Verification, so a backup from an older version is brought up to date. <code>.htaccess</code> and <code>web.config</code> files are never deleted.</li>
        <li>This install's backup settings (location, passphrase, schedule), its Files storage settings and the backup history are kept as they are now, not taken from the backup.</li>
        <li>Maintenance mode switches off and the restore is listed in the history.</li>
    </ol>
    <p>If the restore fails part way, the safety backup is put back automatically and FreeITSM is as it was. If that fails too, FreeITSM stays in maintenance mode and the progress page says which safety backup to restore from the command line (below); the administrators are emailed. If the server is restarted during a restore, it does not continue: the progress page says so and lets you switch maintenance mode off once you have checked the install. It is never switched off while the restore is still running.</p>
    <p>On the server, <code>php scripts/backup_maintenance.php</code> shows what a restore is doing, and <code>--off</code> switches maintenance mode off once it has stopped - for when no browser can (the session that started it has gone). When the safety backup has to be put back by hand, use <code>php scripts/backup_restore.php --set=&lt;safety backup&gt; --force</code>; a command-line restore pauses scheduled backups and gives the install a new backup id, so turn backups back on here and remove older backups from the target yourself when they are no longer needed.</p>
    <div class="help-note">If the backup was made with a different encryption key, its key replaces this install's (the restored settings need it); the page warns before you start. Maintenance mode is kept in a file beside the encryption key, so that folder must be writable by the web server.</div>
    <h4>Onto a new server (command line)</h4>
    <p>Restoring onto a new server is done from the command line with <code>scripts/backup_restore.php</code>. It asks where the backups are, which one, and the passphrase, then restores the encryption key, the database and every file, and runs Database Verification. It only needs the backup location and the passphrase - nothing from the old server.</p>
    <h4>With Docker</h4>
    <ol>
        <li>Set up a new install with the same <code>docker-compose.yml</code>, and add <code>FREEITSM_SCHEDULER=0</code> to the app's environment so no background job runs during the restore.</li>
        <li><code>docker compose up -d</code></li>
        <li><code>docker compose exec app php scripts/backup_restore.php</code></li>
        <li>Remove <code>FREEITSM_SCHEDULER=0</code>, <code>docker compose up -d</code> again, and sign in as before.</li>
    </ol>
    <h4>Without Docker</h4>
    <ol>
        <li>Install FreeITSM, write <code>db_config.php</code> and create an empty database.</li>
        <li><code>php scripts/backup_restore.php</code></li>
        <li>Set up the scheduled task (<code>cron/run.php</code>) and sign in.</li>
    </ol>
    <p>It refuses to overwrite a database that is in use, or a different encryption key that install may need, unless you add <code>--force</code>. <code>--help</code> lists every option, including restoring into a scratch database to try a backup out.</p>
    <div class="help-note">After a restore, scheduled backups are <strong>off</strong> on the restored install, so a trial restore can never remove the original install's backups. Turn them back on here when this is the install you are keeping.</div>
</div>
<?php require __DIR__ . '/_bottom.php'; ?>
