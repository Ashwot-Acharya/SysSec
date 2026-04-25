const fs = require('fs').promises;
const path = require('path');

const dbPath = path.join(__dirname, 'database.json');

async function readDB() {
  try {
    const data = await fs.readFile(dbPath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      const initialData = { users: [], files: [] };
      await writeDB(initialData);
      return initialData;
    }
    throw error;
  }
}

async function writeDB(data) {
  await fs.writeFile(dbPath, JSON.stringify(data, null, 2));
}

module.exports = {
  readDB,
  writeDB
};
