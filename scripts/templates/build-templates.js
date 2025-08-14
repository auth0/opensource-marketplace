const fs = require('fs');
const { z } = require('zod');
const { fromZodError } = require('zod-validation-error');

const getFolders = require('./get-folders');
const buildJSONFromTemplateDirectory = require('./build-json');
const { root, templates_root_path, bundle_path } = require('./base-paths');

// Changes here must be reflected here:
// https://github.com/auth0/managed-marketplace/blob/main/prisma/schema.prisma#L198

const IntegrationTrigger = [
    'POST_LOGIN',
    'CREDENTIALS_EXCHANGE',
    'PRE_USER_REGISTRATION',
    'POST_USER_REGISTRATION',
    'POST_CHANGE_PASSWORD',
    'SEND_PHONE_MESSAGE',
    'IGA_APPROVAL',
    'IGA_CERTIFICATION',
    'IGA_FULFILLMENT_ASSIGNMENT',
    'IGA_FULFILLMENT_EXECUTION',
    'PASSWORD_RESET_POST_CHALLENGE',
    'CUSTOM_TOKEN_EXCHANGE'
];

const UseCase = [
    'MULTIFACTOR',
    'ACTION_FEATURE',
    'ENRICH_PROFILE',
    'ACCESS_CONTROL',
];

const configValue = z.object({
    label: z.string().min(2),
    defaultValue: z.string().min(2),
});
const moduleValue = z.object({
    name: z.string().min(2),
    version: z.string().min(2),
});

const TemplateSchema = z
    .object({
        id: z.string().uuid().optional(),
        name: z.string().min(3),
        triggers: z.array(z.enum(IntegrationTrigger)),
        useCases: z.array(z.enum(UseCase)),
        public: z.boolean().optional(),
        published: z.boolean().optional(),
        deleted: z.boolean().optional(),
        description: z.string().min(3),
        version: z.string().optional(),
        runtime: z.string().optional(),
        secrets: z.array(configValue).optional(),
        config: z.array(configValue).optional(),
        sourceUrl: z.string().url(),
        code: z.string().min(3),
        modules: z.array(moduleValue).optional(),
        notes: z.string().optional(),
    })
    .strict();

const buildTemplates = async () => {
    console.log('\n🗄️   Bundling up all templates.\n');
    const bundle = {};
    try {
        // GET ALL TEMPLATES
        const templates = getFolders(templates_root_path);
        // BUNDLE INTO JSON
        for (const templatePath of templates) {
            const template = await buildJSONFromTemplateDirectory(templatePath);
            // VALIDATE JSON
            try {
                TemplateSchema.parse(template);
            } catch (e) {
                console.error(fromZodError(e));
                process.exit(1);
            }
            bundle[templatePath] = template;
        }
        console.log('\n✅   Bundling complete.\n');
        // OUTPUT JSON PAYLOAD
        fs.mkdirSync(`${root}dist`);
        fs.writeFileSync(`${bundle_path}`, JSON.stringify(bundle));
    } catch (e) {
        console.error('⛔️ - There was an error building templates:', e);
        process.exit(1);
    }
};

module.exports = buildTemplates;
