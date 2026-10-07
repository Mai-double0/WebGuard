// dashboard/cursor-grid.js
// A faint grid behind the site banner: cells near the pointer light up in the
// accent colour, hold briefly, then fade. A click sends a ring across the grid.
// Vanilla port of the idea behind React Bits' CursorGrid; used on the dashboard only.
//
// - The canvas is purely decorative: pointer-events none, aria-hidden. Pointer
//   events are listened for on the banner itself, so clicks and text selection
//   are never blocked.
// - It only animates while something is lit, and not while the tab is hidden.
// - With prefers-reduced-motion it draws the static lattice once and nothing else.
// - The peak opacity is capped so text over a lit line stays above 4.5:1
//   (muted text on the banner measures about 5.0:1 at 0.2).

const DEFAULTS = {
  cellSize: 56,
  radius: 130,
  falloff: 'smooth',     // 'linear' | 'smooth' | 'sharp'
  holdTime: 250,         // ms a lit cell stays before it starts to fade
  fadeDuration: 700,     // ms for a fully lit cell to fade out
  lineWidth: 1,
  maxOpacity: 0.2,
  gridOpacity: 0.05,     // always-visible lattice; 0 hides it
  clickPulse: true,
  pulseSpeed: 520,       // px per second
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
 * Adds the grid canvas as the first child of `banner` and wires it up.
 * Returns a function that removes the canvas, listeners and observers.
 */
export function initCursorGrid(banner, options = {}) {
  if (!banner || typeof HTMLCanvasElement === 'undefined') return () => {};
  const o = { ...DEFAULTS, ...options };
  const ease = FALLOFF[o.falloff] || FALLOFF.linear;

  const canvas = document.createElement('canvas');
  canvas.className = 'cursor-grid-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  banner.prepend(canvas);
  const ctx = canvas.getContext('2d');
  if (!ctx) { canvas.remove(); return () => {}; }

  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

  let w = 0, h = 0, cols = 0, rows = 0, offX = 0, offY = 0;
  let alphas = new Float32Array(0);   // per cell, row-major
  let touched = new Float64Array(0);  // time each cell was last lit
  let color = [255, 255, 255];
  const pulses = [];
  let raf = 0;
  let running = false;
  let lastFrame = 0;
  let listening = false;

  function rebuild() {
    const dpr = Math.min(window.devicePixelRatio || 1, o.maxDpr);
    w = banner.clientWidth;
    h = banner.clientHeight;
    canvas.width = Math.max(1, Math.round(w * dpr));
    canvas.height = Math.max(1, Math.round(h * dpr));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = Math.ceil(w / o.cellSize) + 1;
    rows = Math.ceil(h / o.cellSize) + 1;
    // Centre the lattice so edge cells crop evenly on both sides
    offX = (w - cols * o.cellSize) / 2;
    offY = (h - rows * o.cellSize) / 2;
    alphas = new Float32Array(cols * rows);
    touched = new Float64Array(cols * rows);
    pulses.length = 0;
    color = readColor(o.colorVar);
  }

  function drawLattice() {
    if (o.gridOpacity <= 0) return;
    const [r, g, b] = color;
    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${o.gridOpacity})`;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let c = 0; c <= cols; c++) {
      const x = Math.round(offX + c * o.cellSize) + 0.5;
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
    }
    for (let r2 = 0; r2 <= rows; r2++) {
      const y = Math.round(offY + r2 * o.cellSize) + 0.5;
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
    }
    ctx.stroke();
  }

  // Lights every cell whose centre is within `o.radius` of (x, y).
  function energize(x, y) {
    const s = o.cellSize;
    const r = Math.max(o.radius, 1);
    const now = performance.now();
    const minCol = Math.max(0, Math.floor((x - r - offX) / s));
    const maxCol = Math.min(cols - 1, Math.floor((x + r - offX) / s));
    const minRow = Math.max(0, Math.floor((y - r - offY) / s));
    const maxRow = Math.min(rows - 1, Math.floor((y + r - offY) / s));
    for (let row = minRow; row <= maxRow; row++) {
      for (let col = minCol; col <= maxCol; col++) {
        const i = row * cols + col;
        const dist = Math.hypot(offX + col * s + s / 2 - x, offY + row * s + s / 2 - y);
        if (dist > r) continue;
        const level = ease(1 - dist / r) * o.maxOpacity;
        if (level > alphas[i]) alphas[i] = level;
        if (level > 0) touched[i] = now;
      }
    }
  }

  function draw(now) {
    const dt = Math.min(now - lastFrame, 50);
    lastFrame = now;
    ctx.clearRect(0, 0, w, h);
    drawLattice();

    const s = o.cellSize;
    const half = s / 2;
    const [r, g, b] = color;

    // Click rings hand their energy to the cells they pass over
    for (let pi = pulses.length - 1; pi >= 0; pi--) {
      const p = pulses[pi];
      const ringR = ((now - p.t0) / 1000) * o.pulseSpeed;
      if (ringR > Math.hypot(w, h) + s) { pulses.splice(pi, 1); continue; }
      const minCol = Math.max(0, Math.floor((p.x - ringR - s - offX) / s));
      const maxCol = Math.min(cols - 1, Math.floor((p.x + ringR + s - offX) / s));
      const minRow = Math.max(0, Math.floor((p.y - ringR - s - offY) / s));
      const maxRow = Math.min(rows - 1, Math.floor((p.y + ringR + s - offY) / s));
      for (let row = minRow; row <= maxRow; row++) {
        for (let col = minCol; col <= maxCol; col++) {
          const i = row * cols + col;
          const dist = Math.hypot(offX + col * s + half - p.x, offY + row * s + half - p.y);
          if (Math.abs(dist - ringR) < half && o.maxOpacity > alphas[i]) {
            alphas[i] = o.maxOpacity;
            touched[i] = now;
          }
        }
      }
    }

    let anyLit = pulses.length > 0;
    const fadeStep = (dt / Math.max(o.fadeDuration, 16)) * o.maxOpacity;
    ctx.lineWidth = o.lineWidth;

    for (let i = 0; i < alphas.length; i++) {
      let a = alphas[i];
      if (a <= 0) continue;
      if (now - touched[i] > o.holdTime) {
        a = Math.max(0, a - fadeStep);
        alphas[i] = a;
        if (a <= 0) continue;
      }
      anyLit = true;

      const cx = offX + (i % cols) * s + half;
      const cy = offY + Math.floor(i / cols) * s + half;
      const grad = ctx.createRadialGradient(cx, cy, half * 0.1, cx, cy, s);
      grad.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${a})`);
      grad.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);
      ctx.strokeStyle = grad;
      ctx.strokeRect(cx - half + 0.5, cy - half + 0.5, s - 1, s - 1);
    }

    if (anyLit && !document.hidden) {
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
    const rect = banner.getBoundingClientRect();
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
    } else {
      // Resume only if something is still lit
      if (pulses.length || alphas.some(a => a > 0)) wake();
    }
  }

  function paintStatic() {
    ctx.clearRect(0, 0, w, h);
    drawLattice();
  }

  const resizeObserver = new ResizeObserver(() => {
    rebuild();
    paintStatic();
  });

  // Interactive mode vs reduced-motion mode, switchable at runtime.
  function applyMotionPreference() {
    if (motionQuery.matches) {
      if (listening) {
        banner.removeEventListener('pointermove', onPointerMove);
        banner.removeEventListener('pointerdown', onPointerDown);
        document.removeEventListener('visibilitychange', onVisibility);
        listening = false;
      }
      stop();
      alphas.fill(0);
      pulses.length = 0;
      paintStatic();
    } else if (!listening) {
      banner.addEventListener('pointermove', onPointerMove);
      banner.addEventListener('pointerdown', onPointerDown);
      document.addEventListener('visibilitychange', onVisibility);
      listening = true;
    }
  }

  rebuild();
  paintStatic();
  applyMotionPreference();
  motionQuery.addEventListener('change', applyMotionPreference);
  resizeObserver.observe(banner);

  return function destroy() {
    stop();
    resizeObserver.disconnect();
    motionQuery.removeEventListener('change', applyMotionPreference);
    banner.removeEventListener('pointermove', onPointerMove);
    banner.removeEventListener('pointerdown', onPointerDown);
    document.removeEventListener('visibilitychange', onVisibility);
    listening = false;
    canvas.remove();
  };
}
