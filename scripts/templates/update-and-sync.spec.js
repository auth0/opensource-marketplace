const fs = require('fs');

const updateAndSync = require('./update-and-sync');
const { faker } = require('@faker-js/faker');
const { axiosClient } = require('./api-clients');

jest.mock('fs');
jest.mock('./api-clients');

describe('Script: UpdateAndSync', () => {
    const mockBundle = {
        name: 'Template Name',
        triggers: ['POST_LOGIN'],
        useCases: ['MULTIFACTOR', 'ENRICH_PROFILE'],
        description:
            'Minim sint qui consequat minim. Eiusmod nulla anim ipsum laboris sunt est Lorem laborum officia. Consectetur duis ad officia non pariatur in incididunt sit ea incididunt sit ut qui laboris ut. Pariatur veniam sunt excepteur laboris dolore in non excepteur amet. Minim eu officia anim ea amet cillum nulla ea labore pariatur ipsum. Laboris eu ea minim elit sit ullamco ipsum nostrud cupidatat ad consectetur duis.',
        secrets: [{ label: 'SOME_SECRET', defaultValue: 'value' }],
        sourceUrl:
            'https://github.com/auth0/os-marketplace/tree/main/templates/foo',
        code: '/** * Handler that will be called during the execution of a PostLogin flow. * * @param {Event} event - Details about the user and the context in which they are logging in. * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login. */ exports.onExecutePostLogin = async (event, api) => { };   /** * Handler that will be invoked when this action is resuming after an external redirect. If your * onExecutePostLogin function does not perform a redirect, this function can be safely ignored. * * @param {Event} event - Details about the user and the context in which they are logging in. * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login. */ // exports.onContinuePostLogin = async (event, api) => { // };',
        modules: [{ name: 'axios', version: '0.1.6' }],
        notes: '### Title\n\nElit ullamco fugiat laboris est dolore sunt do. Exercitation mollit anim laboris quis exercitation excepteur exercitation ea incididunt qui. Do anim eiusmod ut voluptate quis sint ad ex commodo. Laborum esse magna Lorem nostrud fugiat consectetur aliqua tempor exercitation elit anim laboris cupidatat amet nisi.\n\n1. `CELPA` Sunt dolore tempor enim esse minim sint officia.\n1. `TAULPT` Cillum excepteur dolor commodo sint proident velit.\n1. `CAHIT` Exercitation consectetur pariatur culpa tempor.',
    };
    const mockManifest = `name: "${mockBundle.name}"\ntriggers: "${mockBundle.triggers}"\nuseCases: "${mockBundle.useCases}"\ndescription: "${mockBundle.description}"\nsecrets: "${mockBundle.secrets}"\nsourceUrl: "${mockBundle.sourceUrl}"\ncode: "${mockBundle.code}"\nmodules: "${mockBundle.modules}"\nnotes: "${mockBundle.notes}"`;

    const mockWriteFileSync = jest.fn();
    const mockId = faker.string.uuid();

    beforeEach(() => {
        fs.readFileSync.mockReturnValueOnce(mockManifest);
        fs.writeFileSync.mockImplementation(mockWriteFileSync);
        axiosClient.post.mockResolvedValue({ data: { id: mockId } });
        axiosClient.get.mockResolvedValue({ data: mockBundle });
        axiosClient.patch.mockResolvedValue({ data: mockBundle });
    });
    it('create a new template from the bundle when there is no id.', async () => {
        await updateAndSync(mockBundle, 'template-1');
        expect(axiosClient.post).toHaveBeenCalled();
        const [[, newManifest]] = mockWriteFileSync.mock.calls;
        expect(newManifest).toEqual(`id: '${mockId}'\n${mockManifest}`);
    });
    it('update a template from the bundle when there is an id.', async () => {
        await updateAndSync({ ...mockBundle, id: mockId }, 'template-1');
        const templateUrl = `templates/${mockId}`;
        expect(axiosClient.get).toHaveBeenCalledWith(templateUrl);
        expect(axiosClient.patch).toHaveBeenCalledWith(templateUrl, {
            id: mockId,
            ...mockBundle,
        });
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });
});
