const { kebabCase } = require('lodash');
const uuid = require('uuid');

const TRIGGERS = [
    'POST_LOGIN',
    'CREDENTIALS_EXCHANGE',
    'PRE_USER_REGISTRATION',
    'POST_USER_REGISTRATION',
    'POST_CHANGE_PASSWORD',
    'SEND_PHONE_MESSAGE',
    'PASSWORD_RESET_POST_CHALLENGE',
    'CUSTOM_TOKEN_EXCHANGE',
];

module.exports = {
    prompt: ({ inquirer }) => {
        const questions = [
            {
                type: 'input',
                name: 'name',
                message:
                    "Please provide a concise title for the actions template you'd like to create. For example: 'Quadruple Factor Authentication'",
            },
            {
                type: 'input',
                name: 'description',
                message:
                    "Please provide a short description of this actions template. For example: 'Enforces quadruple factor authentication when John Doe logs in on a Tuesday'",
            },
            {
                type: 'input',
                name: 'trigger',
                message: `What trigger is this actions template for? Your options are: ${TRIGGERS.map((t) => `\n   ${t}`).join('')}`,
            },
        ];

        return inquirer.prompt(questions).then((answers) => {
            const { name, description, trigger } = answers;
            const id = uuid.v4();

            let error = false;

            if (!name) {
                console.log('Must specify a name for your actions template');
                error = true;
            }

            if (!description) {
                console.log('Must specify a name for your actions template');
                error = true;
            }

            if (TRIGGERS.indexOf(trigger) === -1) {
                console.log(
                    'Must specify a valid trigger for your actions template'
                );
                error = true;
            }

            if (error) {
                throw new Error('inout validation failed');
            }

            const fileName = kebabCase(name);

            return {
                ...answers,
                id,
                name,
                description,
                trigger,
                fileName,
            };
        });
    },
};
