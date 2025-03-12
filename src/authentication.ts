import { Database, sqlite3 } from "sqlite3";
import * as bcrypt from "bcrypt";
import * as crypto from "crypto";
import { mkdir } from "fs";

const saltRounds = 12;

async function authenticate(
	username: string,
	password: string,
	db: Database
): Promise<string> {
	return new Promise((resolve, reject) => {
		db.get(
			"SELECT * FROM users WHERE username = ?",
			[username],
			(error: Error, row: any) => {
				if (row === undefined) {
					resolve("");
					return;
				}

				bcrypt.compare(
					password,
					row["password"],
					(error: Error | undefined, result: boolean) => {
						if (error) {
							resolve("");
							console.log(error);
							return;
						}

						if (result) {
							const token: string = crypto.randomBytes(64).toString("base64");
							resolve(token);
						} else {
							reject("Invalid password");
						}
					}
				);
			}
		);
	});
}

async function registerUser(
	username: string,
	password: string,
	db: Database
): Promise<boolean> {
	const hashedPassword = (await bcrypt.hash(password, saltRounds)).toString();

	return new Promise((resolve, reject) => {
		db.get(
			"SELECT * FROM users WHERE username = ?",
			[username],
			(error: Error, rows: any) => {
				if (rows === undefined || rows["username"] === undefined) {
					const insertSql =
						"INSERT INTO users (username, password) VALUES (?, ?);";

					db.run(insertSql, [username, hashedPassword]);
					mkdir("user_data/" + username, () => {});
					resolve(true);
					return;
				}

				reject("Username in use");
			}
		);
	});
}

async function getUserFromToken(token: string, db: Database): Promise<string> {
	return new Promise((resolve, reject) => {
		db.get(
			"SELECT * FROM users WHERE login_id = ?",
			[token],
			(error: Error, rows: any) => {
				if (rows === undefined) {
					reject("Invalid token");
					return;
				}

				const username: string = rows["username"];
				resolve(username);
			}
		);
	});
}

module.exports = {
	authenticate,
	registerUser,
	getUserFromToken,
};
