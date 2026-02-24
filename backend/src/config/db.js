import mysql from "mysql2/promise"; // for async-await
import dotenv, { config } from "dotenv";

dotenv config();

export const pool = mysql.createPool({

})