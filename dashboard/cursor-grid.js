// dashboard/cursor-grid.js
// A grid behind the page: a faint always-visible lattice, plus lines near the
// pointer that light up in the accent colour, hold briefly and fade, with a soft
// glow under the cursor. A click sends a ring across the grid.
// Vanilla port of the idea behind React Bits' CursorGrid; used on the dashboard only.
//
// - The canvas is purely decorative (CSS makes it fixed, behind the content,
//   pointer-events none; aria-hidden). Pointer events are listened for on
//   `target` (the document), so clicks and text selection are never blocked.
// - It only animates while something is lit, and not while the tab is hidden.
// - With prefers-reduced-motion it draws the static lattice and nothing else.
//
// Text contrast: text sits directly on the grid in places (page headings, the
// header). Every pixel of the canvas is drawn at most once by the lines (each
// segment is its own rect, so lines never overlap, not even at crossings) plus
// at most the glow, so the brightest possible pixel is
//     1 - (1 - maxOpacity) * (1 - glowOpacity)  =  0.278 with the defaults,
// i.e. the accent mixed 28% into the page background. Muted text on that
// measures 4.7:1 and accent text 4.6:1 (AA needs 4.5:1). Do not raise that
// bound above 0.28 without re-checking contrast.

const DEFAULTS = {
  cellSize: 64,
  radius: 240,
  falloff: 'smooth',     // 'linear' | 'smooth' | 'sharp'
  holdTime: 350,         // ms a lit line stays before it starts to fade
  fadeDuration: 900,     // ms for a fully lit line to fade out
  maxOpacity: 0.24,      // peak opacity of a lit line
  gridOpacity: 0.08,     // always-visible lattice; 0 hides it
  glowOpacity: 0.05,     // soft glow under the pointer; 0 disables it
  clickPulse: true,
  pulseSpeed: 700,       // px per second
  maxDpr: 2,
  colorVar: '--accent',
};

const FALLOFF = {
  linear: t => t,
  smooth: t => t * t * (3 - 2 * t),
  sharp: t => t * t * t,
};

// Reads a CSS colour custom property as [r, g, b]. Handles #rgb, #rrggbb and rgb().
function readColor(name) {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const hex = raw.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hex) {
    const h = hex[1].length === 3 ? [...hex[1]].map(c => c + c).join('') : hex[1];
    const n = parseInt(h, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  const rgb = raw.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/i);
  if (rgb) return [+rgb[1], +rgb[2], +rgb[3]];
  return [255, 255, 255];
}

/**
 * Adds the grid canvas as the first child of `container` and wires it up.
 * The canvas fills whatever box the CSS gives it. Pointer events are
 * listened for on `options.target` (default: `container`).
 * Returns a function that removes the canvas, listeners and observers.
 */
export function initCursorGrid(container, options = {}) {
  if (!container || typeof HTMLCanvasElement === 'undefined') return () => {};
  const { target = container, ...rest } = options;
  const o = { ...DEFAULTS, ...rest };
  const ease = FALLOFF[o.falloff] || FALLOFF.linear;

  const canvas = document.createElement('canvas');
  canvas.className = 'cursor-grid-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  container.prepend(canvas);
  const ctx = canvas.getContext('2d');
  if (!ctx) { canvas.remove(); return () => {}; }

  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

  let w = 0, h = 0;
  let xs = new Float32Array(0);       // x of each vertical line
  let ys = new Float32Array(0);       // y of each horizontal line
  // Segments: V = vertical, H = horizontal. Midpoints, current level and the
  // time each was last lit.
  let vN = 0, hN = 0;
  let vMx = new Float32Array(0), vMy = new Float32Array(0);
  let hMx = new Float32Array(0), hMy = new Float32Array(0);
  let vLevel = new Float32Array(0), hLevel = new Float32Array(0);
  let vTouched = new Float64Array(0), hTouched = new Float64Array(0);
  let color = [255, 255, 255];
  const glow = { x: 0, y: 0, level: 0, touched: 0 };
  const pulses = [];
  let raf = 0;
  let running = false;
  let lastFrame = 0;
  let listening = false;

  function rebuild() {
    const dpr = Math.min(window.devicePixelRatio || 1, o.maxDpr);
    w = canvas.clientWidth;
    h = canvas.clientHeight;
    canvas.width = Math.max(1, Math.round(w * dpr));
    canvas.height = Math.max(1, Math.round(h * dpr));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const s = o.cellSize;
    const cols = Math.ceil(w / s) + 1;
    const rows = Math.ceil(h / s) + 1;
    // Centre the lattice so edge cells crop evenly on both sides
    const offX = (w - cols * s) / 2;
    const offY = (h - rows * s) / 2;
    xs = Float32Array.from({ length: cols + 1 }, (_, c) => Math.round(offX + c * s));
    ys = Float32Array.from({ length: rows + 1 }, (_, r) => Math.round(offY + r * s));

    vN = (cols + 1) * rows;
    hN = cols * (rows + 1);
    vMx = new Float32Array(vN); vMy = new Float32Array(vN);
    hMx = new Float32Array(hN); hMy = new Float32Array(hN);
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c <= cols; c++) {
        vMx[r * (cols + 1) + c] = xs[c] + 0.5;
        vMy[r * (cols + 1) + c] = (ys[r] + ys[r + 1]) / 2;
      }
    }
    for (let r = 0; r <= rows; r++) {
      for (let c = 0; c < cols; c++) {
        hMx[r * cols + c] = (xs[c] + xs[c + 1]) / 2;
        hMy[r * cols + c] = ys[r] + 0.5;
      }
    }
    vLevel = new Float32Array(vN); hLevel = new Float32Array(hN);
    vTouched = new Float64Array(vN); hTouched = new Float64Array(hN);
    glow.level = 0;
    pulses.length = 0;
    color = readColor(o.colorVar);
  }

  // Lights every segment whose midpoint is within `o.radius` of (x, y).
  function energize(x, y) {
    const r = Math.max(o.radius, 1);
    const now = performance.now();
    const light = (mx, my, level, touched, n) => {
      for (let i = 0; i < n; i++) {
        const dist = Math.hypot(mx[i] - x, my[i] - y);
        if (dist > r) continue;
        const l = ease(1 - dist / r) * o.maxOpacity;
        if (l > level[i]) level[i] = l;
        if (l > 0) touched[i] = now;
      }
    };
    light(vMx, vMy, vLevel, vTouched, vN);
    light(hMx, hMy, hLevel, hTouched, hN);
    glow.x = x; glow.y = y; glow.level = 1; glow.touched = now;
  }

  // Click rings light the segments they pass over
  function pulseSegments(p, ringR, now) {
    const band = o.cellSize / 2;
    const touch = (mx, my, level, touched, n) => {
      for (let i = 0; i < n; i++) {
        if (Math.abs(Math.hypot(mx[i] - p.x, my[i] - p.y) - ringR) < band && o.maxOpacity > level[i]) {
          level[i] = o.maxOpacity;
          touched[i] = now;
        }
      }
    };
    touch(vMx, vMy, vLevel, vTouched, vN);
    touch(hMx, hMy, hLevel, hTouched, hN);
  }

  // Fades segments that have been lit for longer than holdTime. Returns true
  // while any segment is still lit.
  function fade(level, touched, n, now, step) {
    let lit = false;
    for (let i = 0; i < n; i++) {
      let a = level[i];
      if (a <= 0) continue;
      if (now - touched[i] > o.holdTime) {
        a = Math.max(0, a - step);
        level[i] = a;
        if (a <= 0) continue;
      }
      lit = true;
    }
    return lit;
  }

  function paint() {
    ctx.clearRect(0, 0, w, h);
    const [r, g, b] = color;
    const rgb = `rgb(${r}, ${g}, ${b})`;

    if (o.glowOpacity > 0 && glow.level > 0) {
      const a = o.glowOpacity * glow.level;
      const grad = ctx.createRadialGradient(glow.x, glow.y, 0, glow.x, glow.y, o.radius * 1.2);
      grad.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${a})`);
      grad.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);
    }

    // Each segment is its own rect and no two share a pixel: vertical
    // segments own the crossing pixel, horizontal ones start after it.
    ctx.fillStyle = rgb;
    const cols = xs.length - 1;
    const rows = ys.length - 1;
    for (let rI = 0; rI < rows; rI++) {
      for (let c = 0; c <= cols; c++) {
        const a = Math.max(o.gridOpacity, vLevel[rI * (cols + 1) + c]);
        if (a <= 0) continue;
        ctx.globalAlpha = a;
        ctx.fillRect(xs[c], ys[rI], 1, ys[rI + 1] - ys[rI]);
      }
    }
    for (let rI = 0; rI <= rows; rI++) {
      for (let c = 0; c < cols; c++) {
        const a = Math.max(o.gridOpacity, hLevel[rI * cols + c]);
        if (a <= 0) continue;
        ctx.globalAlpha = a;
        ctx.fillRect(xs[c] + 1, ys[rI], xs[c + 1] - xs[c] - 1, 1);
      }
    }
    ctx.globalAlpha = 1;
  }

  function draw(now) {
    const dt = Math.min(now - lastFrame, 50);
    lastFrame = now;

    for (let pi = pulses.length - 1; pi >= 0; pi--) {
      const p = pulses[pi];
      const ringR = ((now - p.t0) / 1000) * o.pulseSpeed;
      if (ringR > Math.hypot(w, h) + o.cellSize) { pulses.splice(pi, 1); continue; }
      pulseSegments(p, ringR, now);
    }

    const step = (dt / Math.max(o.fadeDuration, 16)) * o.maxOpacity;
    const vLit = fade(vLevel, vTouched, vN, now, step);
    const hLit = fade(hLevel, hTouched, hN, now, step);
    if (glow.level > 0 && now - glow.touched > o.holdTime) {
      glow.level = Math.max(0, glow.level - dt / Math.max(o.fadeDuration, 16));
    }

    paint();

    if ((vLit || hLit || glow.level > 0 || pulses.length) && !document.hidden) {
      raf = requestAnimationFrame(draw);
    } else {
      running = false;   // idle: the last frame (lattice only) stays on screen
    }
  }

  function wake() {
    if (running || document.hidden) return;
    running = true;
    lastFrame = performance.now();
    raf = requestAnimationFrame(draw);
  }

  function stop() {
    cancelAnimationFrame(raf);
    running = false;
  }

  function localPoint(e) {
    const rect = canvas.getBoundingClientRect();
    return [e.clientX - rect.left, e.clientY - rect.top];
  }

  function onPointerMove(e) {
    const [x, y] = localPoint(e);
    energize(x, y);
    wake();
  }

  function onPointerDown(e) {
    if (!o.clickPulse) return;
    const [x, y] = localPoint(e);
    pulses.push({ x, y, t0: performance.now() });
    wake();
  }

  function onVisibility() {
    if (document.hidden) {
      stop();
    } else if (pulses.length || glow.level > 0 || vLevel.some(a => a > 0) || hLevel.some(a => a > 0)) {
      wake();   // resume only if something is still lit
    }
  }

  function clearLit() {
    vLevel.fill(0); hLevel.fill(0);
    glow.level = 0;
    pulses.length = 0;
  }

  const resizeObserver = new ResizeObserver(() => {
    rebuild();
    paint();
  });

  // Interactive mode vs reduced-motion mode, switchable at runtime.
  function applyMotionPreference() {
    if (motionQuery.matches) {
      if (listening) {
        target.removeEventListener('pointermove', onPointerMove);
        target.removeEventListener('pointerdown', onPointerDown);
        document.removeEventListener('visibilitychange', onVisibility);
        listening = false;
      }
      stop();
      clearLit();
      paint();
    } else if (!listening) {
      target.addEventListener('pointermove', onPointerMove);
      target.addEventListener('pointerdown', onPointerDown);
      document.addEventListener('visibilitychange', onVisibility);
      listening = true;
    }
  }

  rebuild();
  paint();
  applyMotionPreference();
  motionQuery.addEventListener('change', applyMotionPreference);
  resizeObserver.observe(canvas);

  return function destroy() {
    stop();
    resizeObserver.disconnect();
    motionQuery.removeEventListener('change', applyMotionPreference);
    target.removeEventListener('pointermove', onPointerMove);
    target.removeEventListener('pointerdown', onPointerDown);
    document.removeEventListener('visibilitychange', onVisibility);
    listening = false;
    canvas.remove();
  };
}
