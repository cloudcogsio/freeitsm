<?php
/**
 * Branding — the organisation's logo, and the login screen designer.
 *
 * TWO JOBS, ONE FILE, because they answer the same question from different
 * angles: "what does this install look like to somebody who has not logged in?"
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. brandingLogoUrl()  — the logo, wherever it is shown
 * ─────────────────────────────────────────────────────────────────────────────
 * Branding has been able to store a logo for a long time, and almost nothing
 * read it: `assets/images/CompanyLogo.png` was hardcoded in NINE places and
 * exactly one page (the asset handover) looked the setting up. So an
 * administrator uploaded a logo, saw it saved, and it appeared essentially
 * nowhere (GH #87). One function now answers it for every caller.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *  2. The login screen designer
 * ─────────────────────────────────────────────────────────────────────────────
 * 🔴 THE SECURITY RULE THIS FILE EXISTS TO ENFORCE:
 *
 *      THE ADMINISTRATOR SUPPLIES VALUES, NEVER SYNTAX.
 *
 * The login page is the one page an attacker can view anonymously, and the one
 * page where every user types a password. Stored XSS there is the worst kind
 * there is: it runs unauthenticated, for everybody, on the credential form. So
 * nothing an administrator types is ever treated as HTML or as CSS.
 *
 * Every setting below declares a TYPE and its permitted values, and
 * brandingLoginDesign() refuses anything else — a colour is `#rrggbb` or it is
 * the default, a position is one of a fixed list or it is the default, a number
 * is clamped, and text is plain text that the page escapes on the way out. The
 * page turns those values into CSS; the administrator never writes any.
 *
 * ⚠️ Validation happens at RENDER as well as at save. Saving is guarded, but a
 * value that reached the row by some other route — a restored backup, a direct
 * UPDATE, an injection elsewhere — still cannot reach the page. This mirrors
 * includes/landing.php, which took the same position for the same reason: "the
 * stored value is a KEY, never a path… anything unrecognised falls back to the
 * default". That is the doctrine for anything the front door reads.
 *
 * ⚠️ And the line NOT to cross: no "custom CSS" and no "custom HTML" field,
 * however often it is asked for. Every guarantee above is void the moment one
 * exists. If something cannot be expressed, the answer is another structured
 * control, not an escape hatch.
 *
 * 🔑 LOCKOUT IS A REAL HAZARD. White text on a white background, or a logo
 * scaled over the form, and nobody can sign in to undo it — including the
 * administrator who did it. `login.php?nobranding=1` always renders the stock
 * screen. It is not a secret and it is not a bypass: it changes appearance
 * only, and is documented next to the settings.
 */

require_once __DIR__ . '/functions.php';

/** The bundled logo, used when no custom one is configured. */
const BRANDING_DEFAULT_LOGO = 'assets/images/CompanyLogo.png';

/** Where an uploaded logo or background may live. Anything outside is refused. */
const BRANDING_UPLOAD_DIR = 'system/uploads/branding/';

/**
 * The organisation's OWN logo as a web URL, or null when none has been set - for
 * documents that should carry the organisation's logo or nothing, never
 * FreeITSM's (GH #254: an exported article showed FreeITSM's logo).
 */
function brandingCustomLogoUrl(?PDO $conn = null): ?string
{
    $url = brandingLogoUrl($conn);
    $base = defined('BASE_URL') ? BASE_URL : '/';
    return $url === $base . BRANDING_DEFAULT_LOGO ? null : $url;
}

/**
 * The organisation's logo as a web URL, with the bundled one as the fallback.
 *
 * ⚠️ Never throws and never returns empty: a page that cannot reach the database
 * still has to render. A missing logo is cosmetic; a fatal on the login page is
 * not.
 */
function brandingLogoUrl(?PDO $conn = null): string
{
    static $cached = null;
    if ($cached !== null) return $cached;

    $base = defined('BASE_URL') ? BASE_URL : '/';
    $cached = $base . BRANDING_DEFAULT_LOGO;

    try {
        $conn = $conn ?: connectToDatabase();
        $s = $conn->prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'branding_logo_path'");
        $s->execute();
        $rel = (string)($s->fetchColumn() ?: '');
        // The stored value must be a file we put there, and must still exist —
        // a pointer to a deleted upload would render a broken image on the login
        // page, which looks like a broken install.
        if ($rel !== '' && brandingPathIsSafe($rel) && file_exists(__DIR__ . '/../' . $rel)) {
            $cached = $base . $rel;
        }
    } catch (Exception) {
        // Fall through to the bundled logo.
    }
    return $cached;
}

/**
 * A stored upload pointer is only ever a file inside the branding directory.
 *
 * @param string $rel  the stored upload path, relative to the app root
 */
function brandingPathIsSafe(string $rel): bool
{
    if (!str_starts_with($rel, BRANDING_UPLOAD_DIR)) return false;
    if (str_contains($rel, '..')) return false;
    if (str_contains($rel, "\0")) return false;
    return (bool)preg_match('/^[A-Za-z0-9._\/-]+$/', $rel);
}

/**
 * THE THREE SCREENS, and what each one has to style.
 *
 * They are not identical: a landing page has no sign-in form, so asking where
 * to put one — or whether its panel should be frosted glass — is a control that
 * cannot do anything. `only` names the fields a scope leaves out.
 *
 * ⚠️ The KEY PREFIX for the analyst login stays `branding_login_` rather than
 * becoming `branding_analyst_`. Renaming it would orphan the settings of anyone
 * who has already used the designer, for tidiness.
 */
function brandingScopes(): array
{
    return [
        'login'  => ['prefix' => 'branding_login_',  'page' => 'auth/login.php'],
        'portal' => ['prefix' => 'branding_portal_', 'page' => 'self-service/login.php'],
        // No form on this one, so no form position and no panel style.
        'home'   => ['prefix' => 'branding_home_',   'page' => 'index.php',
                     // …and one line under the welcome heading is all that page has.
                     'omit'   => ['form_position', 'card_style', 'subheading2'],
                     // …and it keeps the theme's own background unless asked otherwise.
                     'defaults' => ['bg_style' => 'theme']],
    ];
}

/**
 * Returns the scope when it is one of the branded screens (login, portal, home), otherwise 'login'.
 *
 * @param string $scope  the screen asked for, possibly from the request - login, portal or home
 */
function brandingScopeValid(string $scope): string
{
    return isset(brandingScopes()[$scope]) ? $scope : 'login';
}
/**
 * THE VALIDATION TABLE — the single source of truth for the login designer.
 *
 * 🔑 One table drives the save endpoint, the renderer AND the settings form, so
 * a control cannot be added to the screen and forgotten in validation. That is
 * the failure this shape exists to make impossible: an unvalidated field on the
 * login page is precisely the hole the rest of this file is about.
 *
 * Types:
 *   enum   one of `values`
 *   colour #rrggbb
 *   int    clamped to min..max
 *   text   plain text, trimmed, cut to `max` characters — NEVER HTML
 *   upload a path inside the branding directory that still exists
 *
 * @param string $scope  which screen - login, portal or home; anything else is treated as login
 */
function brandingLoginFields(string $scope = 'login'): array
{
    $spec     = brandingScopes()[brandingScopeValid($scope)];
    $omit     = $spec['omit'] ?? [];
    $defaults = $spec['defaults'] ?? [];
    $fields = [
        // ---- layout ----
        'form_position'   => ['type' => 'enum',   'default' => 'centre', 'values' => ['left', 'centre', 'right']],
        'card_style'      => ['type' => 'enum',   'default' => 'solid',  'values' => ['solid', 'glass', 'flat']],

        // ---- background ----
        // ⭐ `theme` means "do not set a background at all", which is the default
        // on the landing page: that page already has a theme-aware background WITH
        // a dark-mode variant, and overriding it by default would break dark mode
        // for every install as a side effect of adding a setting. Opt in, do not
        // opt out.
        'bg_style'        => ['type' => 'enum',   'default' => 'gradient', 'values' => ['theme', 'gradient', 'solid', 'image']],
        // 🔑 The defaults ARE the gradient login.php used to hardcode, so an
        // install that never opens the designer looks exactly as it always did.
        // Shipping a new look to everybody as a side effect of adding a setting
        // is the kind of change nobody asked for and everybody notices.
        'bg_from'         => ['type' => 'colour', 'default' => '#667eea'],
        'bg_to'           => ['type' => 'colour', 'default' => '#764ba2'],
        'bg_direction'    => ['type' => 'enum',   'default' => 'diagonal', 'values' => ['down', 'right', 'diagonal', 'diagonal-up', 'radial']],
        'bg_image_path'   => ['type' => 'upload', 'default' => ''],
        // How much to darken a background image so the form stays legible on top
        // of a busy photograph. 0 = untouched.
        'bg_dim'          => ['type' => 'int',    'default' => 30, 'min' => 0, 'max' => 80],

        // ---- logo ----
        // 250 for the same reason as the gradient above: it is what the page
        // already used, so nothing moves on an install that never touches this.
        //
        // 🔑 BOTH ARE MAXIMA, and the logo is drawn as large as it can be without
        // exceeding either. One control cannot serve both logo shapes: the
        // bundled logo is 1124×301, so its WIDTH is what needs holding back —
        // but a square or portrait logo sized to 250px wide is 250px TALL, and
        // swallows a 400px card. Reported by a customer whose logo is square.
        // Constraining the height is the natural way to think about that one,
        // and a single dimension cannot express it.
        //
        // ⚠️ Two fixed dimensions would DISTORT the logo, so neither is fixed —
        // the aspect ratio is the browser's to keep. The cost is that a logo
        // smaller than the setting is no longer stretched up to meet it, which
        // is the better behaviour anyway: enlarging a bitmap only blurs it.
        'logo_size'       => ['type' => 'int',    'default' => 250, 'min' => 40, 'max' => 400],
        // 0 = no limit, which is the old behaviour exactly — the height was
        // never constrained, so an install that does not touch this sees no
        // change at all.
        'logo_height'     => ['type' => 'int',    'default' => 0,   'min' => 0,  'max' => 400],
        'logo_position'   => ['type' => 'enum',   'default' => 'above', 'values' => ['above', 'top-left', 'top-centre', 'hidden']],

        // ---- words ----
        'heading'         => ['type' => 'text',   'default' => '', 'max' => 80],
        'subheading'      => ['type' => 'text',   'default' => '', 'max' => 160],
        // A second line under the first (GH #150). On the portal it replaces
        // "Sign in to view your tickets" when set; empty keeps that default.
        'subheading2'     => ['type' => 'text',   'default' => '', 'max' => 160],
        'accent'          => ['type' => 'colour', 'default' => '#2b88d8'],

        // ---- banner strip ----
        'banner_position' => ['type' => 'enum',   'default' => 'off', 'values' => ['off', 'top', 'bottom']],
        'banner_text'     => ['type' => 'text',   'default' => '', 'max' => 160],
        'banner_bg'       => ['type' => 'colour', 'default' => '#111827'],
        'banner_fg'       => ['type' => 'colour', 'default' => '#ffffff'],

        // ---- footer strip ----
        'footer_text'     => ['type' => 'text',   'default' => '', 'max' => 200],
        'footer_fg'       => ['type' => 'colour', 'default' => '#ffffff'],
    ];
    foreach ($omit as $f) unset($fields[$f]);
    foreach ($defaults as $f => $v) if (isset($fields[$f])) $fields[$f]['default'] = $v;
    return $fields;
}

/**
 * `form_position` → the settings key it is stored under, for this screen.
 *
 * @param string $field  a field name from brandingLoginFields(), e.g. 'form_position'
 * @param string $scope  which screen - login, portal or home; anything else is treated as login
 */
function brandingLoginKey(string $field, string $scope = 'login'): string
{
    return brandingScopes()[brandingScopeValid($scope)]['prefix'] . $field;
}

/**
 * One value, validated against its declared type. Anything that does not fit
 * becomes the default — never an error, because this runs on the login page.
 *
 * @param string $field  the field's name; not used by the check itself
 * @param mixed $raw  the stored or posted value (untrusted); null or '' gives the default
 * @param array $spec  the field's entry from brandingLoginFields() - type, default, and values/min/max as the type needs
 */
function brandingLoginValidate(string $field, $raw, array $spec)
{
    $default = $spec['default'];
    if ($raw === null || $raw === '') {
        // An empty text field is a legitimate "nothing here", not a fallback.
        return in_array($spec['type'], ['text', 'upload'], true) ? $default : $default;
    }
    $raw = is_string($raw) ? trim($raw) : $raw;

    switch ($spec['type']) {
        case 'enum':
            return in_array($raw, $spec['values'], true) ? $raw : $default;

        case 'colour':
            // Strict. "Starts with #" is not validation — `#fff; background:url(…)`
            // starts with # too.
            return preg_match('/^#[0-9a-fA-F]{6}$/', $raw) ? strtolower($raw) : $default;

        case 'int':
            if (!preg_match('/^-?\d+$/', (string)$raw)) return $default;
            return max($spec['min'], min($spec['max'], (int)$raw));

        case 'text':
            // Control characters stripped so a stored newline cannot break out of
            // an attribute even if a future caller forgets to escape.
            $clean = preg_replace('/[\x00-\x1F\x7F]/u', '', (string)$raw);
            return mb_substr($clean, 0, $spec['max']);

        case 'upload':
            return (brandingPathIsSafe((string)$raw) && file_exists(__DIR__ . '/../' . $raw)) ? $raw : $default;
    }
    return $default;
}

/**
 * The whole design, validated. Safe to call on the login page: it swallows any
 * database failure and returns the defaults.
 *
 * @param string $scope  which screen - login, portal or home; anything else is treated as login
 */
function brandingLoginDesign(?PDO $conn = null, string $scope = 'login'): array
{
    $scope  = brandingScopeValid($scope);
    $fields = brandingLoginFields($scope);
    $out = [];
    foreach ($fields as $f => $spec) $out[$f] = $spec['default'];

    try {
        $conn = $conn ?: connectToDatabase();
        $keys = array_map(fn($f) => brandingLoginKey($f, $scope), array_keys($fields));
        $place = implode(',', array_fill(0, count($keys), '?'));
        // ⚠️ Only these keys. system_settings also holds encrypted SMTP and OAuth
        // credentials; a widened query here would be a leak on the most public
        // page in the product.
        $stmt = $conn->prepare("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ($place)");
        $stmt->execute($keys);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $prefix = brandingScopes()[$scope]['prefix'];
            $field  = substr($row['setting_key'], strlen($prefix));
            if (!isset($fields[$field])) continue;
            $out[$field] = brandingLoginValidate($field, $row['setting_value'], $fields[$field]);
        }
    } catch (Exception) {
        // Defaults. A login screen that cannot be styled still has to be usable.
    }
    return $out;
}

/**
 * The design as CSS custom properties.
 *
 * 🔑 String concatenation is safe HERE and only here, because every value
 * reaching this function has already been through brandingLoginValidate(): a
 * colour matched `#rrggbb`, a direction was one of five words, a number was
 * clamped. Nothing else may be interpolated into CSS.
 *
 * @param array $d  a design from brandingLoginDesign(), every value already validated
 */
function brandingLoginCss(array $d): string
{
    $dirs = [
        'down'        => 'linear-gradient(180deg, %1$s, %2$s)',
        'right'       => 'linear-gradient(90deg, %1$s, %2$s)',
        'diagonal'    => 'linear-gradient(135deg, %1$s, %2$s)',
        'diagonal-up' => 'linear-gradient(45deg, %1$s, %2$s)',
        // ⚠️ %% — a literal percent has to be escaped in a sprintf template.
        // Written as `30% 30%` the second one was eaten ('% 3' reads as a format
        // spec) and the server produced `circle at 30%,` while the browser preview,
        // which builds the same string without sprintf, produced the full one.
        // Still valid CSS either way, which is exactly why it would have gone
        // unnoticed — and a preview that disagrees with the page is the one thing
        // this design is supposed to rule out.
        'radial'      => 'radial-gradient(circle at 30%% 30%%, %1$s, %2$s)',
    ];

    // `theme` emits no background at all, leaving the page's own — including
    // its dark-mode variant — exactly as it was.
    $css = [];
    if ($d['bg_style'] === 'theme') {
        $bg = null;
    } elseif ($d['bg_style'] === 'solid') {
        $bg = $d['bg_from'];
    } elseif ($d['bg_style'] === 'image' && $d['bg_image_path'] !== '') {
        $base = defined('BASE_URL') ? BASE_URL : '/';
        // The path is validated to the branding directory and to a conservative
        // character set, so it cannot close the url() or start a new declaration.
        $bg = "url('" . $base . $d['bg_image_path'] . "') center/cover no-repeat";
    } else {
        $bg = sprintf($dirs[$d['bg_direction']] ?? $dirs['diagonal'], $d['bg_from'], $d['bg_to']);
    }

    if ($bg !== null) $css[] = '--login-bg: ' . $bg;
    $css = array_merge($css, [
        '--login-accent: ' . $d['accent'],
        '--login-logo-size: ' . (int)$d['logo_size'] . 'px',
        // `none` rather than a very large number: the page reads this straight
        // into a max-height, and "no limit" is a value CSS already has a word
        // for. 0 is the stored form because the control is a slider.
        '--login-logo-height: ' . ((int)$d['logo_height'] > 0 ? (int)$d['logo_height'] . 'px' : 'none'),
        // ⚠️ ONLY over an image. The dim exists so a form stays legible on top
        // of a busy photograph; applied to a gradient it just darkens the two
        // colours the administrator chose, which looks like the picker is
        // broken. Caught on a screenshot: a #0f172a→#38bdf8 gradient came out
        // almost black.
        '--login-dim: ' . ($d['bg_style'] === 'image' ? ((int)$d['bg_dim'] / 100) : 0),
        '--login-banner-bg: ' . $d['banner_bg'],
        '--login-banner-fg: ' . $d['banner_fg'],
        '--login-footer-fg: ' . $d['footer_fg'],
    ]);
    return implode('; ', $css) . ';';
}

/**
 * One-click starting points.
 *
 * ⭐ Presets are the difference between a settings screen and a designer. Facing
 * eighteen empty controls is a chore; picking "Sunrise" and then nudging it is
 * enjoyable, and it is also how somebody who is not a designer ends up with
 * something that looks deliberate. Every value here goes through the same
 * validation as a typed one — a preset is a shortcut, not a trusted path.
 */
function brandingLoginPresets(): array
{
    return [
        'midnight' => ['label' => 'Midnight',  'bg_style' => 'gradient', 'bg_from' => '#0f172a', 'bg_to' => '#1e3a5f', 'bg_direction' => 'diagonal',    'accent' => '#38bdf8', 'card_style' => 'glass', 'form_position' => 'centre'],
        'sunrise'  => ['label' => 'Sunrise',   'bg_style' => 'gradient', 'bg_from' => '#f97316', 'bg_to' => '#fbbf24', 'bg_direction' => 'diagonal-up', 'accent' => '#b45309', 'card_style' => 'solid', 'form_position' => 'right'],
        'forest'   => ['label' => 'Forest',    'bg_style' => 'gradient', 'bg_from' => '#064e3b', 'bg_to' => '#10b981', 'bg_direction' => 'down',        'accent' => '#059669', 'card_style' => 'glass', 'form_position' => 'left'],
        'ocean'    => ['label' => 'Ocean',     'bg_style' => 'gradient', 'bg_from' => '#0c4a6e', 'bg_to' => '#22d3ee', 'bg_direction' => 'radial',      'accent' => '#0891b2', 'card_style' => 'glass', 'form_position' => 'centre'],
        'plum'     => ['label' => 'Plum',      'bg_style' => 'gradient', 'bg_from' => '#4c1d95', 'bg_to' => '#db2777', 'bg_direction' => 'diagonal',    'accent' => '#a21caf', 'card_style' => 'solid', 'form_position' => 'centre'],
        'mono'     => ['label' => 'Mono',      'bg_style' => 'solid',    'bg_from' => '#f3f4f6', 'bg_to' => '#f3f4f6', 'bg_direction' => 'down',        'accent' => '#111827', 'card_style' => 'flat',  'form_position' => 'centre'],
    ];
}

/**
 * Is this pair of colours legible together? WCAG relative-luminance contrast.
 *
 * Not a gate — an administrator may have a reason — but the designer says so
 * before it is saved, because the failure mode is people who cannot read the
 * login screen and cannot tell you why.
 *
 * @param string $hexA  the first colour as #rrggbb
 * @param string $hexB  the second colour as #rrggbb
 */
function brandingContrastRatio(string $hexA, string $hexB): float
{
    $lum = function (string $hex): float {
        $c = [];
        foreach ([1, 3, 5] as $i) {
            $v = hexdec(substr($hex, $i, 2)) / 255;
            $c[] = $v <= 0.03928 ? $v / 12.92 : pow(($v + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * $c[0] + 0.7152 * $c[1] + 0.0722 * $c[2];
    };
    $a = $lum($hexA);
    $b = $lum($hexB);
    return (max($a, $b) + 0.05) / (min($a, $b) + 0.05);
}

/* =============================================================================
 * 3. THE INTERFACE: Classic or Modern, and the brand colour.
 *
 * Branding -> Interface. Classic is FreeITSM as it has always looked, and is
 * what every install gets until an administrator chooses otherwise: with
 * Classic nothing below prints a byte. Modern gives every module the same
 * header, with the organisation's logo and colour (renderWaffleMenuButton()
 * prints it, assets/css/shell.css styles it).
 *
 * Same doctrine as the login designer above: the administrator supplies a
 * VALUE (one of two words, a #rrggbb), never CSS, and the value is checked
 * again when it is shown, so a row that arrived some other way still cannot
 * reach the page.
 * ========================================================================== */

/** The accent Modern uses when no brand colour is set - FreeITSM's own blue. */
const BRANDING_DEFAULT_BRAND = '#0078d4';

/** The Modern dark raised surface. Dark accents are checked against it. */
const BRANDING_DARK_SURFACE = '#161b22';

/**
 * A colour as lower-case #rrggbb, or null when it is anything else.
 *
 * @param mixed $v  the submitted or stored value
 */
function brandingValidHex($v): ?string
{
    return is_string($v) && preg_match('/^#[0-9a-fA-F]{6}$/', $v) ? strtolower($v) : null;
}

/**
 * 'modern' only for exactly 'modern'; anything else is Classic.
 *
 * @param mixed $v  the submitted or stored value
 */
function brandingValidInterface($v): string
{
    return $v === 'modern' ? 'modern' : 'classic';
}

/** brandingInterface()'s per-request cache, by reference so tests can clear it. */
function &brandingInterfaceCache(): ?array
{
    static $cache = null;
    return $cache;
}

/** Forget what brandingInterface() read - for tests that change the rows. */
function brandingInterfaceReset(): void
{
    $c = &brandingInterfaceCache();
    $c = null;
}

/**
 * The install's interface choice, read once per request.
 *
 * ⚠️ Never throws: the header of every page calls this. A database that cannot
 * be read is Classic, which is what the page looked like before this existed.
 *
 * @return array{mode: string, primary: string, dark_logo: ?string}
 */
function brandingInterface(?PDO $conn = null): array
{
    $cache = &brandingInterfaceCache();
    if ($cache !== null) return $cache;

    $out = ['mode' => 'classic', 'primary' => BRANDING_DEFAULT_BRAND, 'dark_logo' => null];
    try {
        $conn = $conn ?: connectToDatabase();
        $s = $conn->prepare(
            "SELECT setting_key, setting_value FROM system_settings
              WHERE setting_key IN ('branding_interface', 'branding_brand_primary', 'branding_logo_dark_path')"
        );
        $s->execute();
        $rows = $s->fetchAll(PDO::FETCH_KEY_PAIR);
        $out['mode'] = brandingValidInterface($rows['branding_interface'] ?? null);
        $out['primary'] = brandingValidHex($rows['branding_brand_primary'] ?? null) ?? BRANDING_DEFAULT_BRAND;
        $rel = (string)($rows['branding_logo_dark_path'] ?? '');
        if ($rel !== '' && brandingPathIsSafe($rel) && file_exists(__DIR__ . '/../' . $rel)) {
            $out['dark_logo'] = (defined('BASE_URL') ? BASE_URL : '/') . $rel;
        }
    } catch (Throwable) {
        // Classic, as above.
    }
    return $cache = $out;
}

/** The logo for dark backgrounds as a web URL, or null when none is set. */
function brandingDarkLogoUrl(?PDO $conn = null): ?string
{
    return brandingInterface($conn)['dark_logo'];
}

/** Cache-buster for the Modern stylesheets (modern-base, shell, portal, auth). */
const BRANDING_MODERN_CSS_V = 11;

/**
 * The brand colours as CSS, light and dark, worked out from the one Branding
 * colour - and, when a dark logo is set, a dark-mode rule that shows it in
 * place of the organisation logo wherever a page draws that logo as an <img>
 * (the home page, the Files desktop, the portal bar). Matched on the image's
 * src, so a company's own logo (Files, the portal's logo) is never swapped.
 *
 * Every value is a validated #rrggbb or a path checked to letters, digits and
 * . _ / : - only, so nothing in it came from a person as text.
 *
 * @param array $ui  brandingInterface()
 */
function brandingModernCss(array $ui): string
{
    $d = brandingDeriveAccent($ui['primary']);
    $vars = fn(array $s) => '--accent:' . $s['accent'] . ';--accent-hover:' . $s['hover']
        . ';--accent-soft:' . $s['soft'] . ';--on-accent:' . $s['on'] . ';--accent-text:' . $s['text'];
    $css = ':root[data-ui="modern"]{' . $vars($d['light']) . '}'
         . ':root[data-ui="modern"][data-theme-mode="dark"]{' . $vars($d['dark']) . '}';
    $safe = '/^[A-Za-z0-9._\/:-]+$/';
    if ($ui['dark_logo'] !== null && preg_match($safe, $ui['dark_logo'])) {
        try { $org = brandingLogoUrl(); } catch (Throwable) { $org = ''; }
        if ($org !== '' && preg_match($safe, $org)) {
            $css .= ':root[data-ui="modern"][data-theme-mode="dark"] :is(img.company-logo,img.fd-logo,.portal-brand img,.portal-page-logo img)[src="'
                  . $org . '"]{content:url("' . $ui['dark_logo'] . '")}';
        }
    }
    return $css;
}

/**
 * What a Modern page prints first thing in <body>: the attributes every Modern
 * rule hangs on, the stylesheets, and the brand colours. A stylesheet linked in
 * the body holds back what follows it until it has loaded, so nothing paints in
 * Classic first.
 *
 * @param array  $ui     brandingInterface()
 * @param string $page   'app', 'portal' or 'auth' - set as data-ui-page
 * @param array  $sheets stylesheets after modern-base.css, e.g. ['shell.css']
 * @param string $css    more CSS for the <style> (already safe - see callers)
 * @param array  $attrs  more data-* on <html>, name => fixed word
 */
function brandingModernHead(array $ui, string $page, array $sheets, string $css = '', array $attrs = []): string
{
    $base = htmlspecialchars((defined('BASE_URL') ? BASE_URL : '/') . 'assets/css/');
    $js = "document.documentElement.dataset.ui='modern';document.documentElement.dataset.uiPage='" . preg_replace('/[^a-z]/', '', $page) . "';";
    foreach ($attrs as $k => $v) {
        $js .= 'document.documentElement.dataset.' . preg_replace('/[^A-Za-z]/', '', $k) . "='" . preg_replace('/[^a-z-]/', '', $v) . "';";
    }
    $out = '<script>' . $js . "</script>\n";
    foreach (array_merge(['modern-base.css'], $sheets) as $f) {
        $out .= '<link rel="stylesheet" href="' . $base . htmlspecialchars($f) . '?v=' . BRANDING_MODERN_CSS_V . '">' . "\n";
    }
    return $out . '<style id="ui-brand">' . brandingModernCss($ui) . $css . "</style>\n";
}

/**
 * The Modern look on a sign-in page (analyst and portal sign-in, MFA, password
 * forgot / reset / change, SSO confirm, register, verify). One line after
 * <body> on each page. Prints nothing with Classic, with ?nobranding=1
 * ($disabled - the safety valve must always give the stock screen), or if
 * anything at all goes wrong: these pages must always render.
 *
 * The login designer keeps the background, card style, positions, logo and
 * strips. Its STOCK background (the purple gradient, or "Theme") is treated as
 * "not designed" and Modern's own is used; any other background is kept. Not
 * in the designer's live preview, where the admin is changing it.
 *
 * @param ?array $design    the page's brandingLoginDesign(), or null for a page
 *                          the designer does not style
 * @param bool   $disabled  ?nobranding=1
 * @param bool   $preview   ?preview=1 (the designer's live preview)
 */
function renderModernAuthHead(?array $design = null, bool $disabled = false, bool $preview = false): void
{
    if ($disabled) return;
    try {
        $ui = brandingInterface();
        if ($ui['mode'] !== 'modern') return;
        $stock = $design === null
            || ($design['bg_style'] ?? '') === 'theme'
            || (($design['bg_style'] ?? '') === 'gradient'
                && strcasecmp((string)($design['bg_from'] ?? ''), '#667eea') === 0
                && strcasecmp((string)($design['bg_to'] ?? ''), '#764ba2') === 0);
        echo brandingModernHead($ui, 'auth', ['auth.css'], '', $stock && !$preview ? ['uiBg' => 'modern'] : []);
    } catch (Throwable) {
        // Classic.
    }
}

/**
 * The Modern look on the self-service portal: self-service/includes/header.php
 * calls this after <body>. Nothing with Classic or on any error.
 */
function renderModernPortalHead(): void
{
    try {
        $ui = brandingInterface();
        if ($ui['mode'] !== 'modern') return;
        echo brandingModernHead($ui, 'portal', ['portal.css']);
    } catch (Throwable) {
        // Classic.
    }
}

/**
 * The interface fields of a Branding save, checked before anything is written.
 * Only the fields the form sent: an older client leaves them alone.
 *
 * @param array $post  the request's POST fields
 * @return array<string, ?string>  setting_key => value (null clears it)
 * @throws InvalidArgumentException  on a value that is not one of the allowed ones
 */
function brandingInterfaceFromPost(array $post): array
{
    $out = [];
    if (array_key_exists('interface', $post)) {
        if (!in_array($post['interface'], ['classic', 'modern'], true)) {
            throw new InvalidArgumentException("'interface' must be classic or modern");
        }
        $out['branding_interface'] = $post['interface'];
    }
    if (array_key_exists('brand_primary', $post)) {
        if ($post['brand_primary'] === '') {
            $out['branding_brand_primary'] = null;
        } else {
            $hex = brandingValidHex($post['brand_primary']);
            if ($hex === null) throw new InvalidArgumentException("'brand_primary' must be a colour like #0078d4");
            $out['branding_brand_primary'] = $hex;
        }
    }
    return $out;
}

/**
 * #rrggbb -> [h 0-360, s 0-100, l 0-100].
 *
 * @param string $hex  #rrggbb
 */
function brandingHexToHsl(string $hex): array
{
    $r = hexdec(substr($hex, 1, 2)) / 255;
    $g = hexdec(substr($hex, 3, 2)) / 255;
    $b = hexdec(substr($hex, 5, 2)) / 255;
    $max = max($r, $g, $b);
    $min = min($r, $g, $b);
    $l = ($max + $min) / 2;
    $h = 0.0; $s = 0.0;
    if ($max !== $min) {
        $d = $max - $min;
        $s = $l > 0.5 ? $d / (2 - $max - $min) : $d / ($max + $min);
        if ($max === $r)     $h = (($g - $b) / $d + ($g < $b ? 6 : 0));
        elseif ($max === $g) $h = (($b - $r) / $d + 2);
        else                 $h = (($r - $g) / $d + 4);
        $h *= 60;
    }
    return [$h, $s * 100, $l * 100];
}

/** [h, s, l] -> #rrggbb, lightness and saturation clamped to 0-100. */
function brandingHslToHex(float $h, float $s, float $l): string
{
    $s = max(0, min(100, $s)) / 100;
    $l = max(0, min(100, $l)) / 100;
    $c = (1 - abs(2 * $l - 1)) * $s;
    $x = $c * (1 - abs(fmod($h / 60, 2) - 1));
    $m = $l - $c / 2;
    [$r, $g, $b] = match (true) {
        $h < 60  => [$c, $x, 0],
        $h < 120 => [$x, $c, 0],
        $h < 180 => [0, $c, $x],
        $h < 240 => [0, $x, $c],
        $h < 300 => [$x, 0, $c],
        default  => [$c, 0, $x],
    };
    return sprintf('#%02x%02x%02x', (int)round(($r + $m) * 255), (int)round(($g + $m) * 255), (int)round(($b + $m) * 255));
}

/** $pct per cent of $hex mixed into $base, as #rrggbb. */
function brandingMix(string $hex, string $base, float $pct): string
{
    $out = '#';
    foreach ([1, 3, 5] as $i) {
        $a = hexdec(substr($hex, $i, 2));
        $b = hexdec(substr($base, $i, 2));
        $out .= sprintf('%02x', (int)round($b + ($a - $b) * $pct / 100));
    }
    return $out;
}

/** The text colour that reads (>= 4.5:1) on $bg: white, else near-black, else null. */
function brandingOnColour(string $bg): ?string
{
    if (brandingContrastRatio('#ffffff', $bg) >= 4.5) return '#ffffff';
    if (brandingContrastRatio('#111111', $bg) >= 4.5) return '#111111';
    return null;
}

/**
 * Everything Modern needs from one brand colour, for light and dark.
 *
 * For each of light and dark, in 4-point steps of HSL lightness:
 *  - accent: the colour as given if it shows on the page (>= 3:1 against the
 *    surfaces) and white or near-black text reads on it (>= 4.5:1); otherwise
 *    darkened (light) or lifted (dark) until both hold, and marked `adjusted`
 *    so the Branding page can say so. A pale yellow brand gets a deeper yellow.
 *  - on: the text on the accent (white, else near-black).
 *  - hover: 8 points away from the accent, in whichever direction makes `on`
 *    stronger (darker under white text, lighter under dark text), and further
 *    until `on` still reads on it.
 *  - text: the accent as a text or line colour on the page (links, the current
 *    tab, focus rings), moved until it reads (>= 4.5:1) on the surfaces.
 *  - soft: a tint of the accent on the surface, for selected rows.
 *
 * Mirrored for the Branding page's preview in assets/js/brand-colours.js.
 *
 * @param string $hex  a validated #rrggbb
 * @return array{light: array, dark: array}  each: accent, hover, soft, on, text (#rrggbb), adjusted (bool)
 */
function brandingDeriveAccent(string $hex): array
{
    [$h, $s, $l] = brandingHexToHsl($hex);
    return [
        'light' => brandingDeriveFor($h, $s, $l, -4, ['#ffffff', '#f6f7f9'], '#ffffff'),
        'dark'  => brandingDeriveFor($h, $s, $l, +4, [BRANDING_DARK_SURFACE, '#0f1318'], BRANDING_DARK_SURFACE),
    ];
}

/**
 * One mode's shades for brandingDeriveAccent().
 *
 * @param float  $step      -4 (light: darken) or +4 (dark: lift)
 * @param array  $surfaces  the page surfaces the accent and its text must show on
 * @param string $softBase  the surface the soft tint is mixed into
 */
function brandingDeriveFor(float $h, float $s, float $l, float $step, array $surfaces, string $softBase): array
{
    $shows = function (string $c, float $min) use ($surfaces): bool {
        foreach ($surfaces as $bg) if (brandingContrastRatio($c, $bg) < $min) return false;
        return true;
    };

    // The accent itself.
    $al = $l;
    $accent = brandingHslToHex($h, $s, $al);
    $on = brandingOnColour($accent);
    while ((!$shows($accent, 3.0) || $on === null) && $al > 0 && $al < 100) {
        $al += $step;
        $accent = brandingHslToHex($h, $s, $al);
        $on = brandingOnColour($accent);
    }
    $on ??= $step < 0 ? '#ffffff' : '#111111';
    $adjusted = $accent !== brandingHslToHex($h, $s, $l);

    // Hover: towards stronger contrast with its own text, never the same colour.
    $dir = $on === '#ffffff' ? -1 : 1;
    $hl = max(0, min(100, $al + 8 * $dir));
    $hover = brandingHslToHex($h, $s, $hl);
    while (brandingContrastRatio($on, $hover) < 4.5 && $hl > 0 && $hl < 100) {
        $hl = max(0, min(100, $hl + 4 * $dir));
        $hover = brandingHslToHex($h, $s, $hl);
    }
    if ($hover === $accent) $hover = brandingHslToHex($h, $s, max(0, min(100, $al - 8 * $dir)));

    // The accent as text on the page.
    $tl = $al;
    $text = $accent;
    while (!$shows($text, 4.5) && $tl > 0 && $tl < 100) {
        $tl += $step;
        $text = brandingHslToHex($h, $s, $tl);
    }

    return [
        'accent'   => $accent,
        'hover'    => $hover,
        'soft'     => brandingMix($accent, $softBase, $step < 0 ? 12 : 22),
        'on'       => $on,
        'text'     => $text,
        'adjusted' => $adjusted,
    ];
}
