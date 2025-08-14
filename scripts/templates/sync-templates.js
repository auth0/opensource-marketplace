const fs = require('fs');

const updateAndSync = require('./update-and-sync');
const { bundle_path, templates_root_path } = require('./base-paths');

const syncTemplates = async () => {
    console.log('\n🔄   Syncing All Templates');
    let bundle;
    try {
        bundle = JSON.parse(fs.readFileSync(bundle_path).toString());
    } catch (e) {
        console.error(`\n⛔️   There was an error reading the bundle: ${e}`);
        process.exit(1);
    }
    // BUNDLE CHANGED FILES
    const files = fs.readdirSync(templates_root_path)
    const changedTemplates = new Set();
    for (const file of files) {
        if (file !== '.gitkeep') {
            changedTemplates.add(file);
        }
    }
    // UPDATE OR SYNC
    for (const template of changedTemplates) {
        await updateAndSync(bundle[template], template);
    }
    console.log('\n✅   Syncing complete.\n\n');
};

module.exports = syncTemplates;
