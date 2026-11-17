<?php
/**
 * System Help — Branding.
 */
require __DIR__ . '/_init.php';
$helpSlug = 'branding';
require __DIR__ . '/_top.php';
?>

<!-- 1. Overview -->
<div class="help-section" id="overview">
    <div class="help-section-header"><?php echo helpSectionNum('overview'); ?>
        <div>
            <h3>What branding controls</h3>
            <p>Branding holds two things shared across the whole install: an organisation <strong>logo</strong>, and the default <strong>header and footer text</strong> placed on branded output. These act as the fallback for any module that renders a branded document.</p>
        </div>
    </div>
    <p>Today that means the <strong>Network Mapper</strong> diagram header and footer; future export surfaces (PDF/PNG) read the same settings, so anything you set here applies consistently wherever branded output is produced.</p>
    <div class="help-note"><strong>Where it lives:</strong> System &rarr; Branding. The settings are organisation-wide, so a change here affects every diagram and export across the install.</div>
</div>

<!-- Interface: Classic or Modern -->
<div class="help-section" id="interface">
    <div class="help-section-header"><?php echo helpSectionNum('interface'); ?>
        <div>
            <h3>Interface: Classic or Modern</h3>
            <p><strong>Classic</strong> is the standard FreeITSM look, where each module has its own coloured header. <strong>Modern</strong> gives every module the same light header, with your logo on the left and your brand colour on buttons, links and selections. The sign-in pages and the self-service portal follow it too.</p>
        </div>
    </div>
    <p>Every install starts on Classic. Choose <strong>Modern</strong> in the <strong>Interface</strong> card at the top of this page and press <strong>Save</strong>. It applies to every analyst the next time each page loads. Choose Classic again to go back; nothing else changes.</p>
    <ul>
        <li><strong>Each module keeps its colour.</strong> In Modern it shows as a thin strip along the top of the header, a small square by the module's name, and its tile in the module menu. Colours set in System &rarr; Colours still apply.</li>
        <li><strong>Brand colour.</strong> Type a colour such as <code>#0078d4</code>, use the colour picker, or click one of the colours suggested <strong>From your logo</strong>. The suggestions are read from your logo in your browser. Leave it blank for FreeITSM's standard blue.</li>
        <li><strong>Readable text.</strong> If white text would be hard to read on your colour, buttons use dark text, or a darker shade of your colour, and the card says so. Dark mode uses a lighter shade so it shows on a dark background. The preview shows both.</li>
        <li><strong>Logo for dark backgrounds.</strong> Optional. People who use Dark mode see this one instead of your logo: in the header, on the home page, on the Files desktop and in the portal. A company's own logo is never replaced. Without it, the header logo sits on a small light panel so a dark logo stays visible. PNG or JPG, up to 2MB.</li>
        <li><strong>Light or Dark</strong> is still each person's own choice, in their account menu. Portal users choose theirs in My Account.</li>
        <li><strong>Sign-in pages.</strong> The sign-in, password and registration pages for analysts and the portal take the Modern look. What you set in the sign-in designer below still applies: a background you chose, the card style, positions, logo and banners. The designer's standard purple background is replaced by Modern's own; choose any other background to keep yours. The sign-in pages are always light. Add <code>?nobranding=1</code> to a sign-in address for the plain standard screen.</li>
        <li><strong>Self-service portal.</strong> The portal gets the same light header and your brand colour. A header colour set in System &rarr; Self-service portal shows as the thin strip along the top; its logo and background pattern settings still apply.</li>
    </ul>
    <div class="help-note"><strong>Where Modern shows:</strong> every module's main screens, which share the module header, the home page, the sign-in pages and the self-service portal. A few pop-out and print views have no header and stay as they are.</div>
</div>

<!-- System name -->
<div class="help-section" id="name">
    <div class="help-section-header"><?php echo helpSectionNum('name'); ?>
        <div>
            <h3>System name</h3>
            <p>The first part of every page title - the name in the browser tab and in bookmarks, on every page of every module: <strong>Acme IT - Contracts - Edit contract</strong>. Leave it blank to use <strong>Service Desk</strong>.</p>
        </div>
    </div>
    <p>Type the name in the <strong>System name</strong> card at the top of this page and press <strong>Save</strong>. Titles change the next time each page loads, in every language - only the name itself is yours to set, the rest of each title is translated.</p>
    <div class="help-note"><strong>Moved in 3.5.0:</strong> it used to be under Tickets &rarr; Settings &rarr; General, which now points here. A name you had already set there is kept.</div>
</div>

<!-- Link back to your site (3.5.0) -->
<div class="help-section" id="back-link">
    <div class="help-section-header"><?php echo helpSectionNum('back-link'); ?>
        <div>
            <h3>Link back to your site</h3>
            <p>A small link at the top of the screen back to your own site - the intranet or website people reach FreeITSM from.</p>
        </div>
    </div>
    <p>Fill in the <strong>Link text</strong> (for example <em>Back to the intranet</em>) and the <strong>Address</strong>, choose whether it shows on the <strong>self-service portal</strong>, the <strong>analyst screens</strong> or <strong>both</strong>, and press <strong>Save</strong>. Leave both boxes blank for no link.</p>
    <ul>
        <li>The address must start with <code>https://</code> or <code>http://</code>.</li>
        <li>On the analyst screens, where the navigation bar is already full, it shows as just an arrow on screens narrower than about 1700 pixels - the words appear when you point at it. On a phone the portal shows just the arrow too.</li>
    </ul>
</div>

<!-- 2. Logo -->
<div class="help-section" id="logo">
    <div class="help-section-header"><?php echo helpSectionNum('logo'); ?>
        <div>
            <h3>Logo</h3>
            <p>Upload one image to use as your organisation logo. It's dropped into branded output wherever the <code>{{logo}}</code> token appears.</p>
        </div>
    </div>
    <div class="help-steps">
        <div class="help-step"><div class="help-step-num">1</div><div><strong>Choose a file.</strong> Use the file picker in the Logo card. Accepted formats are <code>PNG</code>, <code>JPG/JPEG</code> and <code>SVG</code>.</div></div>
        <div class="help-step"><div class="help-step-num">2</div><div><strong>Check the preview.</strong> The picked image shows immediately in the preview box so you can confirm it before saving.</div></div>
        <div class="help-step"><div class="help-step-num">3</div><div><strong>Save.</strong> Press <strong>Save</strong> to store it. The preview then reflects whatever is actually on disk.</div></div>
    </div>
    <p>To clear the logo, press <strong>Remove</strong> next to the preview, then <strong>Save</strong>. The preview returns to a "No logo" placeholder.</p>
    <div class="help-note warn"><strong>Size limit:</strong> the logo file must be 2&nbsp;MB or smaller. A larger file is rejected when you pick it. The preview box is roughly 140&times;80, and the logo is scaled to fit — a wide, transparent <code>PNG</code> or <code>SVG</code> reproduces best.</div>
</div>

<!-- 3. Header & footer text -->
<div class="help-section" id="slots">
    <div class="help-section-header"><?php echo helpSectionNum('slots'); ?>
        <div>
            <h3>Header &amp; footer text</h3>
            <p>Two rows of three slots — left, centre and right — for the header and again for the footer. Each slot is plain text, up to 200 characters, and may contain tokens (see below).</p>
        </div>
    </div>
    <div class="help-table"><table>
        <tr><th>Row</th><th>Left</th><th>Centre</th><th>Right</th></tr>
        <tr><td><strong>Header</strong></td><td>Header left slot</td><td>Header centre slot</td><td>Header right slot</td></tr>
        <tr><td><strong>Footer</strong></td><td>Footer left slot</td><td>Footer centre slot</td><td>Footer right slot</td></tr>
    </table></div>
    <p>Leave any slot empty to print nothing in that position. Slots can mix plain text and tokens freely, for example <code>Author: {{author}}</code>.</p>
</div>

<!-- 4. Tokens -->
<div class="help-section" id="tokens">
    <div class="help-section-header"><?php echo helpSectionNum('tokens'); ?>
        <div>
            <h3>Tokens</h3>
            <p>Tokens are placeholders that are replaced with live values when the document is rendered, so one template suits every diagram or export.</p>
        </div>
    </div>
    <div class="help-table"><table>
        <tr><th>Token</th><th>Replaced with</th></tr>
        <tr><td><code>{{logo}}</code></td><td>The uploaded organisation logo.</td></tr>
        <tr><td><code>{{title}}</code></td><td>The title of the diagram or document.</td></tr>
        <tr><td><code>{{author}}</code></td><td>The author of the diagram or document.</td></tr>
        <tr><td><code>{{version}}</code></td><td>The version of the diagram or document.</td></tr>
        <tr><td><code>{{modified}}</code></td><td>The last-modified date.</td></tr>
    </table></div>
    <div class="help-note"><strong>Example:</strong> a footer slot of <code>Author: {{author}}</code> renders as <em>Author:</em> followed by the document's actual author when the output is produced.</div>
</div>

<!-- 5. Saving & resetting -->
<?php /* The three sign-in screens. This page documented only the logo and the
         header/footer text for exported documents, and never mentioned the
         designer that shares the same screen - so the background-image bug in
         #137 landed on a feature with no documentation at all. */ ?>
<div class="help-section" id="screens">
    <div class="help-section-header"><?php echo helpSectionNum('screens'); ?>
        <div>
            <h3>The three sign-in screens</h3>
            <p>Besides the logo, <strong>System &rarr; Branding</strong> designs the three pages people meet before they sign in. Each is configured on its own tab and each is entirely independent.</p>
        </div>
    </div>
    <ul class="help-list">
        <li><strong>Analyst login</strong> &mdash; <code>auth/login.php</code>, the page your team uses.</li>
        <li><strong>Self-service portal</strong> &mdash; <code>self-service/login.php</code>, the page everybody else uses. This is the one your customers see, so it is usually the one worth spending time on.</li>
        <li><strong>Home</strong> &mdash; the landing page at the root of the site, which can be set as the page people arrive at.</li>
    </ul>
    <p>For each you can set a <strong>background</strong> (a colour, a gradient, or an uploaded image), where the sign-in form sits, and how its panel is styled. The Home tab has no form on it, so it offers neither of those last two, and it keeps the theme's own background unless you tell it otherwise.</p>
    <div class="help-note"><strong>Each tab keeps its own settings, including its own background image.</strong> Uploading a picture on the Self-Service Portal tab changes the portal and nothing else. Until 2.0.0 that was not true &mdash; every upload was written to the analyst login screen whichever tab you were on, so the portal's image replaced the analyst one and the portal showed nothing (<a href="https://github.com/edmozley/freeitsm/issues/137" target="_blank" rel="noopener">#137</a>, fixed by Santhosh Srinivasan).</div>
    <p>Press <strong>Save</strong> before switching tabs. Each tab has its own file picker, so a picture chosen on one and left unsaved is not carried over to another.</p>
</div>

<div class="help-section" id="files">
    <div class="help-section-header"><?php echo helpSectionNum('files'); ?>
        <div>
            <h3>Files desktop logo</h3>
            <p>The <strong>Files desktop</strong> card decides the logo shown in the corner of the Files module's desktop - for everybody. People can change their own desktop colour in Files, but not this.</p>
        </div>
    </div>
    <ul class="help-list">
        <li><strong>Logo</strong> - either the logo of the company the person is working in (set per company in <strong>System &rarr; Companies</strong>), falling back to the organisation logo above when that company has none; or <strong>No logo</strong>.</li>
        <li><strong>Position</strong> - top right or bottom right of the desktop.</li>
    </ul>
    <p>It is saved with the rest of the page by <strong>Save</strong>.</p>
</div>

<div class="help-section" id="save">
    <div class="help-section-header"><?php echo helpSectionNum('save'); ?>
        <div>
            <h3>Saving &amp; resetting</h3>
            <p>Changes only take effect once saved. Two buttons sit at the bottom of the page.</p>
        </div>
    </div>
    <div class="help-cards">
        <div class="help-card">
            <h4>Save</h4>
            <p>Stores the logo and all six text slots. A confirmation appears, and the logo preview refreshes to match what's on disk.</p>
        </div>
        <div class="help-card">
            <h4>Reset</h4>
            <p>Restores the header and footer slots to their built-in defaults — the same values a brand-new install starts with. The logo is left untouched.</p>
        </div>
    </div>
    <div class="help-note"><strong>Defaults:</strong> header left <code>{{logo}}</code>, header centre <code>{{title}}</code>; footer left <code>Author: {{author}}</code>, footer centre <code>{{version}}</code>, footer right <code>Modified: {{modified}}</code>. <strong>Reset</strong> fills the boxes with these — you still need to <strong>Save</strong> to apply them.</div>
</div>

<?php require __DIR__ . '/_bottom.php'; ?>
