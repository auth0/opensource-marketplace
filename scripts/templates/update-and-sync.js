const fs = require('fs');
const { templates_root_path } = require('./base-paths');
const { axiosClient } = require('./api-clients');

const updateAndSync = async (templateBundle, templateFolder) => {
    if (!templateBundle || !templateFolder) {
        console.error('No template specified or folder.');
    }
        // CREATE NEW TEMPLATE
        try {
            const {
                data: { id },
            } = await axiosClient.post('/templates', {
                ...templateBundle,
                // APPEND PARTNER ID
                partnerId: process.env.AUTH0_PARTNER_ID,
            });
            newId = id;
            console.log(`Template ${templateBundle.name} created`)
        } catch (e) {
            console.error(`There was an error creating a template ${e}`);
            process.exit(1);
        }
};

module.exports = updateAndSync;
