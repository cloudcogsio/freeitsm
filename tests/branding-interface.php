<?php
/* 🔴 NEVER OVER THE WEB. See tests/README.md. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

/**
 * Branding -> Interface: the Classic / Modern choice, the brand colour and the
 * shades worked out from it, and what the shared header prints for each.
 *
 *   php tests/branding-interface.php
 *   FREEITSM_TEST_DATABASE=<this install's database> php tests/branding-interface.php   (part 2 as well)
 *
 * PART 1 - no database: colour and choice validation, contrast, derived shades.
 * PART 2 - the settings rows: what brandingInterface() reads from them, the save
 *          validator, and the header's output. Every row it touches is put back
 *          as it was, in `finally`.
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/branding.php';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $detail = ''): void
{
    global $pass, $fail;
    if ($cond) { $pass++; echo "  PASS  $what\n"; }
    else       { $fail++; echo "  FAIL  $what" . ($detail !== '' ? "  <- $detail" : '') . "\n"; }
}

echo "PART 1 - validation and colour\n";

ok('a colour is lower-cased', brandingValidHex('#0078D4') === '#0078d4');
foreach (['#FFF', 'red', '#12345g', '', null, ['#000000'], ' #000000', '#0000000'] as $bad) {
    ok('refused: ' . json_encode($bad), brandingValidHex($bad) === null);
}
ok('modern is modern', brandingValidInterface('modern') === 'modern');
foreach (['Modern', ' modern', 'dark', '', null, 1] as $bad) {
    ok('classic for ' . json_encode($bad), brandingValidInterface($bad) === 'classic');
}

ok('white on black is 21:1', round(brandingContrastRatio('#ffffff', '#000000'), 1) === 21.0);
ok('FreeITSM blue on white is 4.53:1', round(brandingContrastRatio('#0078d4', '#ffffff'), 2) === 4.53,
   (string)round(brandingContrastRatio('#0078d4', '#ffffff'), 2));
ok('control: yellow on white fails 4.5', brandingContrastRatio('#ffd400', '#ffffff') < 4.5);

$hex = '/^#[0-9a-f]{6}$/';
foreach (['#0078d4', '#ffd400', '#f5f5f5', '#0a0a0a', '#2b5bd7', '#e11d48', '#10b981'] as $c) {
    $d = brandingDeriveAccent($c);
    $all = array_merge(array_values($d['light']), array_values($d['dark']));
    ok("$c: every shade is #rrggbb", count(array_filter($all, fn($v) => is_string($v) && preg_match($hex, $v))) === 8);
    ok("$c: button text reads in light (>= 4.5)", brandingContrastRatio($d['light']['on'], $d['light']['accent']) >= 4.5,
       $d['light']['on'] . ' on ' . $d['light']['accent']);
    ok("$c: button text reads in dark (>= 4.5)", brandingContrastRatio($d['dark']['on'], $d['dark']['accent']) >= 4.5,
       $d['dark']['on'] . ' on ' . $d['dark']['accent']);
    ok("$c: accent visible on the dark surface (>= 3)", brandingContrastRatio($d['dark']['accent'], '#161b22') >= 3.0,
       $d['dark']['accent']);
}
$y = brandingDeriveAccent('#ffd400');
ok('yellow keeps its colour and takes dark text', $y['light']['accent'] === '#ffd400' && $y['light']['on'] === '#111111');
$b = brandingDeriveAccent('#0078d4');
ok('FreeITSM blue is left as it is, with white text', $b['light']['accent'] === '#0078d4' && $b['light']['on'] === '#ffffff');
$g = brandingDeriveAccent('#7a7a7a');
ok('a mid grey that fits neither text colour is darkened until white reads',
   $g['light']['accent'] !== '#7a7a7a' && $g['light']['on'] === '#ffffff' && $g['light']['adjusted'] === true);
ok('control: an unchanged colour is not marked adjusted', $b['light']['adjusted'] === false);

echo "\nPART 2 - settings, the save validator and the header\n";
$db = getenv('FREEITSM_TEST_DATABASE');
if (!$db || !defined('DB_NAME') || $db !== DB_NAME) {
    echo "  SKIP  set FREEITSM_TEST_DATABASE to this install's database (" . (defined('DB_NAME') ? DB_NAME : '?') . ")\n";
} else {
    $conn = connectToDatabase();
    $keys = ['branding_interface', 'branding_brand_primary', 'branding_logo_dark_path', 'branding_logo_path'];
    $snap = $conn->prepare("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ('" . implode("','", $keys) . "')");
    $snap->execute();
    $saved = $snap->fetchAll(PDO::FETCH_KEY_PAIR);
    $set = function (array $rows) use ($conn, $keys) {
        $conn->exec("DELETE FROM system_settings WHERE setting_key IN ('" . implode("','", $keys) . "')");
        $ins = $conn->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)");
        foreach ($rows as $k => $v) $ins->execute([$k, $v]);
        brandingInterfaceReset();
    };
    try {
        $set([]);
        $i = brandingInterface($conn);
        ok('no rows: Classic, FreeITSM blue, no dark logo', $i['mode'] === 'classic' && $i['primary'] === '#0078d4' && $i['dark_logo'] === null, json_encode($i));

        $set(['branding_interface' => 'modern', 'branding_brand_primary' => '#E11D48']);
        $i = brandingInterface($conn);
        ok('modern + a colour is read', $i['mode'] === 'modern' && $i['primary'] === '#e11d48', json_encode($i));

        $set(['branding_interface' => 'Modern', 'branding_brand_primary' => 'red']);
        $i = brandingInterface($conn);
        ok('junk in the rows falls back', $i['mode'] === 'classic' && $i['primary'] === '#0078d4', json_encode($i));

        $set(['branding_interface' => 'modern', 'branding_logo_dark_path' => 'system/uploads/branding/../../config.php']);
        ok('a dark logo path outside the branding folder is ignored', brandingInterface($conn)['dark_logo'] === null);
        $set(['branding_interface' => 'modern', 'branding_logo_dark_path' => 'system/uploads/branding/zz-missing.png']);
        ok('a dark logo that is not on disk is ignored', brandingInterface($conn)['dark_logo'] === null);

        // The save validator.
        $refused = function (array $post) { try { brandingInterfaceFromPost($post); return false; } catch (InvalidArgumentException) { return true; } };
        ok('save: an unknown interface is refused', $refused(['interface' => 'dark']));
        ok('save: a short colour is refused', $refused(['brand_primary' => '#FFF']));
        ok('save: neither field sent = nothing to change', brandingInterfaceFromPost(['header_left' => 'x']) === []);
        ok('save: good values are normalised', brandingInterfaceFromPost(['interface' => 'modern', 'brand_primary' => '#E11D48'])
            === ['branding_interface' => 'modern', 'branding_brand_primary' => '#e11d48']);
        ok('save: an empty colour clears it', brandingInterfaceFromPost(['brand_primary' => '']) === ['branding_brand_primary' => null]);

        // The header. renderWaffleMenuButton() lives in waffle-menu.php, which prints
        // its stylesheet when included - capture and discard that once.
        $_SESSION = $_SESSION ?? [];
        ob_start();
        require_once __DIR__ . '/../includes/waffle-menu.php';
        ob_end_clean();
        $render = function () { ob_start(); renderWaffleMenuButton(); return ob_get_clean(); };

        $set([]);
        $none = $render();
        $set(['branding_interface' => 'classic']);
        $classic = $render();
        ok('Classic prints the same with or without the row', $none === $classic);
        ok('Classic prints nothing of the Modern shell', !str_contains($classic, 'data-ui') && !str_contains($classic, 'shell.css') && !str_contains($classic, 'ui-brand'));

        $set(['branding_interface' => 'modern', 'branding_brand_primary' => '#e11d48']);
        $modern = $render();
        ok('Modern sets the attribute', str_contains($modern, "dataset.ui='modern'"));
        ok('Modern links the shell stylesheet', (bool)preg_match('/shell\.css\?v=\d+/', $modern));
        ok('Modern carries the brand colour', str_contains($modern, '--accent:#e11d48'));
        ok('Modern gives each module header its colour', str_contains($modern, '.header.tickets-header{--ui-module:'));
        ok('Modern with no logo shows the system name', str_contains($modern, 'ui-brand-name'));
        ok('Modern still prints the button', str_contains($modern, 'class="waffle-btn"'));

        $set(['branding_interface' => 'classic']);
        $conn->exec("UPDATE system_settings SET setting_value = 'modern' WHERE setting_key = 'branding_interface'");
        ok('control: without a reset the request keeps what it read first', !str_contains($render(), 'data-ui'));
    } finally {
        $conn->exec("DELETE FROM system_settings WHERE setting_key IN ('" . implode("','", $keys) . "')");
        $ins = $conn->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)");
        foreach ($saved as $k => $v) $ins->execute([$k, $v]);
        brandingInterfaceReset();
    }
}

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
