const path = require('path');

const bundle_path = path.join(__dirname, './../../dist/bundle.json');
const root = path.join(__dirname, './../../');
const templates_root_path = path.join(__dirname, './../../templates/');

module.exports = {
    templates_root_path,
    root,
    bundle_path,
};
