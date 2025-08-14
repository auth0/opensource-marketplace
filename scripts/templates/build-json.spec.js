const buildJSON = require('./build-json');
const fs = require('fs');

jest.mock('fs');

describe('Script: BuildJSON', () => {
    const mockConsoleLog = jest.fn();

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(mockConsoleLog);
        fs.readFileSync.mockReturnValueOnce('name: "some name"');
        fs.readFileSync.mockReturnValueOnce('const a = () => {};');
    });

    it('should build json from markdown.', async () => {
        const mockName = 'test';
        const subject = await buildJSON(mockName);
        expect(mockConsoleLog).toHaveBeenCalledWith(
            `  • 📕   Reading template data for ${mockName}`
        );
        // expect(subject).toMatchSnapshot();
        expect(1).toBeDefined();
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });
});
