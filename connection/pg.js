const pgp = require('pg-promise')();
// Configure PostgreSQL connection
const db = pgp({
  connectionString: `postgres://${process.env.postgresUser}:${process.env.postgresPwd}@${process.env.testURL}:5432/${process.env.testDB}`,
});

module.exports.db = db