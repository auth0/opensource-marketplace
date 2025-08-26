---
to: "<%= trigger == 'CUSTOM_TOKEN_EXCHANGE' ? `templates/${fileName}-${trigger}/code.js` : null %>"
---

/**
* Handler to be executed while executing a custom token exchange request
* @param {Event} event - Details about the incoming token exchange request.
* @param {CustomTokenExchangeAPI} api - Methods and utilities to define token exchange process.
*/
exports.onExecuteCustomTokenExchange = async (event, api) => {
  // Code goes here
  return;
};
