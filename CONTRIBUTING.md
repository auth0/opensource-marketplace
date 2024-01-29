## Contributing

### Actions Templates

For best practices, please review [our documentaton](https://auth0.com/docs/customize/actions/actions-templates#best-practices) and accompanying coding guidelines

#### Creating an Actions Template

To create a new actions template, follow the steps below:

1. Make sure you have all npm modules installed: `npm i` (from the root of this repo)
2. Generate a new actions template and follow all prompts: `npm run add:template` (from the root of this repo)
3. Open the newly generated `manifest.yaml` file and make sure to update it and fill in any other extra details such as secrets, and notes.
4. Open the newly generated `code.js` file and make sure to add your code implementation within the relevant generated exported functions
5. Make sure to test your `code.js` in a live tenant of your own to make sure it works as expected.
6. Once ready, create a pull request with your new actions template.

#### Updating an Actions Template

1. Locate the directory of the actions template you'd like to update under `templates/*`.
2. Update any details in the `manifest.yaml` or `code.js` contained within.
3. Create a pull request with your changes.

> [!NOTE]
>
> -   You are not allowed to update the `id` if an actions template

#### Deleting an Actions Template

1. Locate the directory of the actions template you'd like to update under `templates/*`.
2. Look within `manifest.yaml` and set the `deleted` field to `true`.
3. Create a pull request with your changes.

#### Actions Template Deployment

The actions team will periodically take the actions templates represented in this repo and deploy them.

> [!NOTE]
>
> There is no pre-determined cadence at which the actions templates in this repository are deployed.
