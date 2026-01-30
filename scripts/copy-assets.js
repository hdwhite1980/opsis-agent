// scripts/copy-assets.js
const fs = require('fs');
const path = require('path');

function copyDir(src, dest) {
  // Create destination directory
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  // Check if source exists
  if (!fs.existsSync(src)) {
    console.log(`Source directory not found: ${src}, skipping...`);
    return;
  }

  // Copy files
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (let entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function copyFile(src, dest) {
  const destDir = path.dirname(dest);
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log(`✓ Copied ${path.basename(src)}`);
  } else {
    console.log(`⚠ File not found: ${src}`);
  }
}

console.log('Copying GUI assets...');

// Create dist/gui directory
const guiDir = path.join(__dirname, '..', 'dist', 'gui');
if (!fs.existsSync(guiDir)) {
  fs.mkdirSync(guiDir, { recursive: true });
}

// Copy HTML file
copyFile(
  path.join(__dirname, '..', 'src', 'gui', 'index.html'),
  path.join(__dirname, '..', 'dist', 'gui', 'index.html')
);

// Copy assets from src/gui/assets (if exists)
const srcAssets = path.join(__dirname, '..', 'src', 'gui', 'assets');
if (fs.existsSync(srcAssets)) {
  copyDir(srcAssets, path.join(__dirname, '..', 'dist', 'gui', 'assets'));
  console.log('✓ Copied src/gui/assets');
}

// Copy assets from root assets folder (if exists)
const rootAssets = path.join(__dirname, '..', 'assets');
if (fs.existsSync(rootAssets)) {
  copyDir(rootAssets, path.join(__dirname, '..', 'dist', 'gui', 'assets'));
  console.log('✓ Copied root assets');
}

console.log('Asset copy complete!');
