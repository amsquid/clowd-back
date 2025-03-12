import { Database, sqlite3 } from "sqlite3";
import * as bcrypt from "bcrypt";
const auth = require("../src/authentication");

const userTableSQL = `
	CREATE TABLE \`users\` (
		\`username\` TEXT(64) NOT NULL PRIMARY KEY UNIQUE DEFAULT '',
		\`password\` TEXT(64) NOT NULL DEFAULT '',
		\`login_id\` BIGINT(20) NOT NULL DEFAULT '0'
	);
`;

const db: Database = new Database(":memory:");
const username: string = "joe";
const password: string = "mama";

beforeAll(async () => {
	await new Promise<void>((resolve, reject) => {
		db.exec(userTableSQL, (error: Error | null) =>
			error ? reject(error) : resolve()
		);
	});

	await auth.registerUser(username, password, db);
});

test("registration added the user", async () => {
	const row = await new Promise<any>((resolve, reject) => {
		db.get(
			"SELECT * FROM users WHERE username=?",
			[username],
			(error: Error | null, row: any) => {
				if (error) reject(error);
				else resolve(row);
			}
		);
	});

	expect(row).toBeTruthy();
});

test("registration password is correct", async () => {
	const dbPassword: string = await new Promise<string>((resolve, reject) => {
		db.get(
			"SELECT * FROM users WHERE username=?",
			[username],
			(error: Error | null, row: any) => {
				if (error) reject(error);
				else resolve(row["password"]);
			}
		);
	});

	const correctPassword: boolean = await bcrypt.compare(password, dbPassword);
	expect(correctPassword).toBe(true);
});

test("login validated", async () => {
	const token: string = await auth.authenticate(username, password, db);
	expect(token).not.toBe("");
});

test("got user token", async () => {
	const token: string = await new Promise<string>((resolve, reject) => {
		db.get(
			"SELECT * FROM users WHERE username=?",
			[username],
			(error: Error | null, row: any) => {
				if (error) reject(error);
				else resolve(row["login_id"]);
			}
		);
	});

	const gottenUsername: string = await auth.getUserFromToken(token, db);
	expect(gottenUsername).toBe(username);
});
