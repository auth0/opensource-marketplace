const fs = require('fs');
const { faker } = require('@faker-js/faker');

const syncTemplates = require('./sync-templates');
const { githubApiClient } = require('./api-clients');
const updateAndSync = require('./update-and-sync');

jest.mock('./api-clients');
jest.mock('./update-and-sync');
jest.mock('fs');

const mockPullsJSON = [
    {
        number: faker.number.int(),
    },
];
const mockFilesJSON = [];

let rand = faker.number.int({ max: 10, min: 1 });
while (rand > 0) {
    mockFilesJSON.push({
        sha: faker.git.commitSha(),
        filename: `templates/template-${faker.lorem.word()}/${faker.system.commonFileName(
            'md'
        )}`,
    });
    rand--;
}

describe('Script: SyncTemplates', () => {
    process.env = {
        GH_PAT: 'token',
    };
    const mockConsoleLog = jest.fn();
    const mockUpdateAndSync = jest.fn();

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(mockConsoleLog);
        fs.readFileSync.mockImplementation(() => ({
            toString: () =>
                '{"template-1":{"name":"Template 1","code":"const a = () => {};"}}',
        }));
        githubApiClient.request.mockImplementationOnce(() =>
            Promise.resolve({ data: mockPullsJSON })
        );
        githubApiClient.request.mockImplementationOnce(() =>
            Promise.resolve({ data: mockFilesJSON })
        );
        updateAndSync.mockImplementation(mockUpdateAndSync);
    });
    xit('should sync the templates from the dist directory.', async () => {
        await syncTemplates();
        expect(updateAndSync).toHaveBeenCalledTimes(mockFilesJSON.length);
        expect(1).toBe(1);
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });
});
