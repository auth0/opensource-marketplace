const fs = require('fs');

const getFolders = require('./get-folders');

jest.mock('fs');

describe('Script: getFolders', () => {
    const mockConsoleLog = jest.fn();
    const mockStatSync = jest.fn();
    const mockFolders = ['test-template'];

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(mockConsoleLog);
        fs.readdirSync.mockImplementation(() => mockFolders);
        fs.statSync.mockImplementation(() => ({
            isDirectory: () => mockStatSync,
        }));
    });
    it('return an array of directories', async () => {
        const subject = getFolders();
        expect(subject).toEqual(mockFolders);
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });
});
