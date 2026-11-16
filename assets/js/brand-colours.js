/**
 * Brand colours - System -> Branding -> Interface.
 *
 * Two jobs for the Branding page:
 *  - brandColoursFromImage(img): suggest brand colours from the organisation's
 *    logo, read from its pixels in the browser. Nothing is sent anywhere; the
 *    administrator picks one and only a #rrggbb is saved.
 *  - brandDerive(hex): the same light/dark shades the server works out
 *    (brandingDeriveAccent() in includes/branding.php), so the preview shows
 *    what Modern will show. The server's copy is the one that counts.
 *
 * The logo is same-origin (system/uploads/branding) or a file just picked
 * (an object URL), so the canvas is never tainted.
 */
(function () {
    'use strict';

    function hexToRgb(hex) {
        return [1, 3, 5].map(i => parseInt(hex.substr(i, 2), 16));
    }
    function rgbToHex(r, g, b) {
        return '#' + [r, g, b].map(v => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('');
    }
    function luminance(hex) {
        const c = hexToRgb(hex).map(v => {
            v /= 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    }
    function contrast(a, b) {
        const x = luminance(a), y = luminance(b);
        return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
    }
    function rgbToHsl(r, g, b) {
        r /= 255; g /= 255; b /= 255;
        const max = Math.max(r, g, b), min = Math.min(r, g, b);
        const l = (max + min) / 2;
        let h = 0, s = 0;
        if (max !== min) {
            const d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            if (max === r) h = (g - b) / d + (g < b ? 6 : 0);
            else if (max === g) h = (b - r) / d + 2;
            else h = (r - g) / d + 4;
            h *= 60;
        }
        return [h, s * 100, l * 100];
    }
    function hslToHex(h, s, l) {
        s = Math.max(0, Math.min(100, s)) / 100;
        l = Math.max(0, Math.min(100, l)) / 100;
        const c = (1 - Math.abs(2 * l - 1)) * s;
        const x = c * (1 - Math.abs((h / 60) % 2 - 1));
        const m = l - c / 2;
        const [r, g, b] = h < 60 ? [c, x, 0] : h < 120 ? [x, c, 0] : h < 180 ? [0, c, x]
                        : h < 240 ? [0, x, c] : h < 300 ? [x, 0, c] : [c, 0, x];
        return rgbToHex((r + m) * 255, (g + m) * 255, (b + m) * 255);
    }
    function mix(hex, base, pct) {
        const a = hexToRgb(hex), b = hexToRgb(base);
        return rgbToHex(...a.map((v, i) => b[i] + (v - b[i]) * pct / 100));
    }
    function onColour(bg) {
        if (contrast('#ffffff', bg) >= 4.5) return '#ffffff';
        if (contrast('#111111', bg) >= 4.5) return '#111111';
        return null;
    }

    const DARK_SURFACE = '#161b22';

    /** Mirrors brandingDeriveAccent() in includes/branding.php. */
    function brandDerive(hex) {
        const [h, s, l] = rgbToHsl(...hexToRgb(hex));
        let accent = hex, on = onColour(accent), ll = l, adjusted = false;
        while (on === null && ll > 0) {
            ll -= 4;
            accent = hslToHex(h, s, ll);
            on = contrast('#ffffff', accent) >= 4.5 ? '#ffffff' : null;
            adjusted = true;
        }
        const light = { accent, hover: hslToHex(h, s, ll - 8), soft: mix(accent, '#ffffff', 12), on: on || '#ffffff', adjusted };

        let dl = l, dAccent = hex, dOn = onColour(dAccent), dAdjusted = false;
        while ((contrast(dAccent, DARK_SURFACE) < 3 || dOn === null) && dl < 100) {
            dl += 4;
            dAccent = hslToHex(h, s, dl);
            dOn = onColour(dAccent);
            dAdjusted = true;
        }
        const dark = { accent: dAccent, hover: hslToHex(h, s, dl + 8), soft: mix(dAccent, DARK_SURFACE, 22), on: dOn || '#111111', adjusted: dAdjusted };
        return { light, dark };
    }

    /**
     * Up to five brand colours from a loaded logo, strongest first.
     * Skips transparent, near-white, near-black and grey pixels; groups the
     * rest into buckets of 4 bits per channel; scores each bucket by how much
     * of the logo it covers times how vivid it is; merges near neighbours.
     *
     * @param {HTMLImageElement} img  a loaded, same-origin image
     * @returns {string[]}  #rrggbb, possibly empty
     */
    function brandColoursFromImage(img) {
        const w0 = img.naturalWidth, h0 = img.naturalHeight;
        if (!w0 || !h0) return [];
        const k = Math.min(1, 128 / Math.max(w0, h0));
        const w = Math.max(1, Math.round(w0 * k)), h = Math.max(1, Math.round(h0 * k));
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(img, 0, 0, w, h);
        let data;
        try { data = ctx.getImageData(0, 0, w, h).data; } catch (e) { return []; }

        const buckets = new Map();
        for (let i = 0; i < data.length; i += 4) {
            if (data[i + 3] < 128) continue;
            const r = data[i], g = data[i + 1], b = data[i + 2];
            const [, s, l] = rgbToHsl(r, g, b);
            if (l > 92 || l < 8 || s < 15) continue;
            const key = (r >> 4) << 8 | (g >> 4) << 4 | (b >> 4);
            const e = buckets.get(key) || { n: 0, r: 0, g: 0, b: 0, s: 0 };
            e.n++; e.r += r; e.g += g; e.b += b; e.s += s;
            buckets.set(key, e);
        }
        const cand = [...buckets.values()].map(e => ({
            r: e.r / e.n, g: e.g / e.n, b: e.b / e.n, n: e.n, score: e.n * (e.s / e.n),
        })).sort((a, b) => b.score - a.score);

        const picked = [];
        for (const c of cand) {
            const near = picked.find(p => Math.hypot(p.r - c.r, p.g - c.g, p.b - c.b) < 48);
            if (near) { near.score += c.score; continue; }
            picked.push(c);
        }
        return picked.sort((a, b) => b.score - a.score).slice(0, 5).map(c => rgbToHex(c.r, c.g, c.b));
    }

    window.brandDerive = brandDerive;
    window.brandColoursFromImage = brandColoursFromImage;
    window.brandContrast = contrast;
})();
