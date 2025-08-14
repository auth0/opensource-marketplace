const { Octokit } = require('@octokit/rest');
const axios = require('axios').default;

const githubApiClient = new Octokit({
    auth: process.env.GH_ACCESS_TOKEN,
});

const axiosClient = axios.create({
    baseURL: process.env.BASE_URL,
    timeout: 5000,
    headers: {
        ["os-sync-key"]: process.env.API_SYNC_KEY,
    },
});

module.exports = {
    githubApiClient,
    axiosClient,
};
