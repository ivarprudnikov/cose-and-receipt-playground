The project is using [Cypress](https://docs.cypress.io/) for the end to end testing. The tests are written in javascript and are run in the CI envinronment in GitHub actions.

To run functional e2e tests locally, follow these steps:

- First, start the local server, from root of the project run: `go run .`
- Then, in another window run cypress through `npx cypress open` (you'll need Node.js installed)
- Use the Cypress application window to select which tests to run