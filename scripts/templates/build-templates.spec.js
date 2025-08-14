const fs = require('fs');

const buildTemplates = require('./build-templates');
const getFolders = require('./get-folders');
const buildJSONFromTemplateDirectory = require('./build-json');
const { root, bundle_path } = require('./base-paths');
const { faker } = require('@faker-js/faker');

jest.mock('fs');
const mockJSON = {
    name: faker.word.noun(),
    triggers: ['POST_LOGIN'],
    useCases: ['MULTIFACTOR', 'ENRICH_PROFILE'],
    description: faker.lorem.paragraph(),
    secrets: [{ label: 'SOME_SECRET', defaultValue: 'value' }],
    sourceUrl: faker.internet.url(),
    code: '/** * Handler that will be called during the execution of a PostLogin flow. * * @param {Event} event - Details about the user and the context in which they are logging in. * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login. */ exports.onExecutePostLogin = async (event, api) => { };   /** * Handler that will be invoked when this action is resuming after an external redirect. If your * onExecutePostLogin function does not perform a redirect, this function can be safely ignored. * * @param {Event} event - Details about the user and the context in which they are logging in. * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login. */ // exports.onContinuePostLogin = async (event, api) => { // };',
    modules: [{ name: 'axios', version: '0.1.6' }],
    notes: faker.lorem.paragraph(),
};
const mockName = 'mock-template';
jest.mock('./get-folders', () => jest.fn(() => [mockName]));
jest.mock('./build-json', () => jest.fn(() => mockJSON));

describe('Script: BuildTemplates', () => {
    const mockConsoleLog = jest.fn();
    const mockMkdirSync = jest.fn();
    const mockWriteFileSync = jest.fn();

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(mockConsoleLog);
        fs.mkdirSync.mockImplementation(mockMkdirSync);
        fs.writeFileSync.mockImplementation(mockWriteFileSync);
    });
    it('should build the templates dist.', async () => {
        await buildTemplates();
        const [[initialCallArgs], [secondCallArgs]] = console.log.mock.calls;
        expect(initialCallArgs).toMatchSnapshot();
        expect(secondCallArgs).toMatchSnapshot();
        expect(fs.mkdirSync).toHaveBeenCalledWith(`${root}dist`);
        const [[path, contents]] = fs.writeFileSync.mock.calls;
        expect(path).toEqual(bundle_path);
        const mockTemplate = {
            [mockName]: mockJSON,
        };
        expect(contents).toEqual(JSON.stringify(mockTemplate));
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });
});
