import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import { Database, OPEN_READWRITE } from "sqlite3";
import { existsSync, writeFile } from "fs";

const auth = require("./authentication");
const cors = require("cors");

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 3000;
const dbFilename = process.env.db_file || "clowd.db";

if (!existsSync(dbFilename)) writeFile(dbFilename, "", () => {});
const db = new Database(dbFilename, OPEN_READWRITE);

db.exec(`
	CREATE TABLE IF NOT EXISTS \`users\` (
		\`username\` TEXT(64) NOT NULL PRIMARY KEY UNIQUE DEFAULT '',
		\`password\` TEXT(64) NOT NULL DEFAULT '',
		\`login_id\` BIGINT(20) NOT NULL DEFAULT '0'
	);	
`);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.get("/", (req: Request, res: Response) => {
	res.send({ data: "Clowd :)" });
});

app.post("/login", (req: Request, res: Response) => {
	const username = req.body.username;
	const password = req.body.password;

	(async () => {
		const token: string = await auth.authenticate(username, password, db);
		const authenticated: boolean = token !== "";

		if (authenticated) {
			db.run("UPDATE users SET login_id=? WHERE username=?", [token, username]);

			res.status(200);
			res.send({ "logged-in": true, token: token });
		} else {
			res.status(401);
			res.send({ "logged-in": false });
		}
	})();
});

app.post("/register", (req: Request, res: Response) => {
	const username = req.body.username;
	const password = req.body.password;

	(async () => {
		const valid = await auth.registerUser(username, password, db);

		if (valid) {
			res.status(200);
		} else {
			res.status(418);
		}

		res.send({ registered: valid });
	})();
});

app.listen(port, () => {
	console.log(`[server] Server is listening on http://localhost:${port}`);
});
