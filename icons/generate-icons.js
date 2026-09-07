const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

function generateIcon(size) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');

  // Background circle — dark navy
  ctx.beginPath();
  ctx.arc(size / 2, size / 2, size / 2, 0, Math.PI * 2);
  ctx.fillStyle = '#0f172a';
  ctx.fill();

  // Inner shield shape
  const cx = size / 2;
  const cy = size / 2;
  const s = size * 0.55;

  ctx.beginPath();
  ctx.moveTo(cx, cy - s * 0.5);
  ctx.lineTo(cx + s * 0.4, cy - s * 0.2);
  ctx.lineTo(cx + s * 0.4, cy + s * 0.1);
  ctx.quadraticCurveTo(cx + s * 0.4, cy + s * 0.5, cx, cy + s * 0.55);
  ctx.quadraticCurveTo(cx - s * 0.4, cy + s * 0.5, cx - s * 0.4, cy + s * 0.1);
  ctx.lineTo(cx - s * 0.4, cy - s * 0.2);
  ctx.closePath();
  ctx.fillStyle = '#3b82f6';
  ctx.fill();

  // Letter G inside shield
  if (size >= 48) {
    ctx.fillStyle = '#ffffff';
    ctx.font = `bold ${Math.floor(size * 0.3)}px Arial`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('W', cx, cy + size * 0.02);
  }

  const outPath = path.join(__dirname, `icon${size}.png`);
  const buffer = canvas.toBuffer('image/png');
  fs.writeFileSync(outPath, buffer);
  console.log(`✓ Generated icon${size}.png`);
}

[16, 48, 128].forEach(generateIcon);
console.log('All icons generated in icons/');
