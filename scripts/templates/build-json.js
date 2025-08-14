const yamlParser = require('js-yaml');
const fs = require('fs');

const { templates_root_path } = require('./base-paths');

const buildJSONFromTemplateDirectory = async (directory) => {
    console.log(`  • 📕   Reading template data for ${directory}`);
    try {
        const yaml = yamlParser.load(
            fs.readFileSync(
                `${templates_root_path}${directory}/manifest.yaml`,
                'utf8'
            )
        );
        const code = fs.readFileSync(
            `${templates_root_path}${directory}/code.js`,
            'utf8'
        );
        return {
            ...yaml,
            code,
        };
    } catch (e) {
        console.error(
            `There was an error trying to parse template: ${directory}`,
            e
        );
    }
};

module.exports = buildJSONFromTemplateDirectory;
