const path = require('path');

const basePaths = require('./base-paths');

describe('Script: BasePaths', () => {
    it('return base paths.', () => {
        expect(basePaths.bundle_path).toEqual(
            path.join(__dirname, './../../dist/bundle.json')
        );
        expect(basePaths.root).toEqual(path.join(__dirname, './../../'));
        expect(basePaths.templates_root_path).toEqual(
            path.join(__dirname, './../../templates/')
        );
    });
});
