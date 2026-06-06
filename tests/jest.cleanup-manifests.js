'use strict';

const fs = require('fs');
const path = require('path');

function getManifestDir() {
    return path.join(process.cwd(), 'infra', 'db', 'export-manifests');
}

function removeManifestFiles() {
    const manifestDir = getManifestDir();

    if (!fs.existsSync(manifestDir)) return;

    for (const entry of fs.readdirSync(manifestDir)) {
        if (!entry.endsWith('.manifest.json')) continue;

        const filePath = path.join(manifestDir, entry);
        try {
            fs.unlinkSync(filePath);
        } catch (err) {
            // Ignore cleanup failures so test runs are never blocked by stale artifacts.
        }
    }
}

module.exports = async () => {
    removeManifestFiles();
};
