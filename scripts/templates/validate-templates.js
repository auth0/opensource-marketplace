const yamlParser = require('js-yaml');
const fs = require('fs');
const path = require('path');
const { z } = require('zod');
const { fromZodError } = require('zod-validation-error');

// Changes here must be reflected here:
// https://github.com/auth0/managed-marketplace/blob/main/prisma/schema.prisma#L198
const IntegrationTrigger = [
    'POST_LOGIN',
    'CREDENTIALS_EXCHANGE',
    'PRE_USER_REGISTRATION',
    'POST_USER_REGISTRATION',
    'POST_CHANGE_PASSWORD',
    'SEND_PHONE_MESSAGE',
    'PASSWORD_RESET_POST_CHALLENGE',
    'CUSTOM_TOKEN_EXCHANGE',
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
        id: z.string().uuid(),
        name: z.string().min(3),
        triggers: z.array(z.enum(IntegrationTrigger)),
        useCases: z.array(z.enum(UseCase)),
        public: z.literal(true),
        deleted: z.boolean().optional(),
        description: z.string().min(3),
        version: z.string().optional(),
        runtime: z.string().optional(),
        secrets: z.array(configValue).optional(),
        sourceUrl: z.string().url(),
        code: z.string().min(3),
        modules: z.array(moduleValue).optional(),
        notes: z.string().optional(),
    })
    .strict();

function templateDirs() {
    const dir = path.normalize(`${__dirname}/../../templates`);

    // Read the contents of the directory
    const items = fs.readdirSync(dir);

    // Filter out only directories (folders)
    return items
        .map((item) => `${dir}/${item}`)
        .filter((item) => {
            return fs.statSync(item).isDirectory();
        });
}

const templateToJSON = async (templateDir) => {
    const yaml = yamlParser.load(
        fs.readFileSync(`${templateDir}/manifest.yaml`, 'utf8')
    );

    const code = fs.readFileSync(`${templateDir}/code.js`, 'utf8');

    return {
        ...yaml,
        code,
    };
};

const validateTemplates = async () => {
    console.log('\n🗄️   Validating schema for all templates.\n');
    try {
        // GET ALL TEMPLATES
        let templates;
        try {
            templates = templateDirs();
        } catch (e) {
            throw {
                detail: 'failed to load templates',
                err: e,
            };
        }

        // BUNDLE INTO JSON
        for (const templatePath of templates) {
            console.log('🗄️   Validating template:', templatePath);

            let template;
            try {
                template = await templateToJSON(templatePath);
            } catch (e) {
                throw {
                    detail: `failed to load template: ${templatePath}`,
                    err: e,
                };
            }

            // VALIDATE JSON
            try {
                TemplateSchema.parse(template);
            } catch (e) {
                throw {
                    detail: `template validation failed, template: ${templatePath}`,
                    err: fromZodError(e),
                };
            }
        }
    } catch (e) {
        console.error(
            '⛔️ - There was an error validatong templates:',
            e.detail,
            '\n\n',
            e.err
        );
        process.exit(1);
    }

    console.log('\n✅   Validation complete.\n');
};

(async function () {
    await validateTemplates();
})();
