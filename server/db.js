import pkg from "pg";

const { Pool } = pkg;

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "aavs_login_db",
  password: "Waheguru23@",
  port: 5432
});

export default pool;