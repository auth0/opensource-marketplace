const fs = require('fs');

const getFolders = (directoryPath) => {
    try {
        // Read the contents of the directory
        const items = fs.readdirSync(directoryPath);

        // Filter out only directories (folders)
        return items.filter((item) => {
            const itemPath = `${directoryPath}/${item}`;
            return fs.statSync(itemPath).isDirectory();
        });
    } catch (error) {
        console.error('Error reading directory:', error);
        return [];
    }
};

module.exports = getFolders;
