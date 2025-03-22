import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import { Database, OPEN_READWRITE } from "sqlite3";
import * as fs from "fs";

const auth = require("./authentication");
const cors = require("cors");

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 3000;
const dbFilename = process.env.db_file || "clowd.db";
const userFolder = process.env.user_folder || "user_data";

if (!fs.existsSync(dbFilename)) fs.writeFile(dbFilename, "", () => {});
if (!fs.existsSync(userFolder)) fs.mkdir(userFolder, () => {});

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
		try {
			const token: string = await auth.authenticate(username, password, db);
			db.run("UPDATE users SET login_id=? WHERE username=?", [token, username]);

			res.status(200);
			res.send({ "logged-in": true, token: token });
		} catch (error) {
			res.status(401);
			res.send({ "logged-in": false, error: error });
		}
	})();
});

app.post("/register", (req: Request, res: Response) => {
	const username = req.body.username;
	const password = req.body.password;

	(async () => {
		try {
			const valid = await auth.registerUser(username, password, db);

			res.status(200);
			res.send({ registered: true });
		} catch (error) {
			res.status(418);
			res.send({ registered: false, error: error });
		}
	})();
});

app.post("/list-files", (req: Request, res: Response) => {
	const token: string = req.body.token;

	(async () => {
		try {
			const username = await auth.getUserFromToken(token, db);
			let filenames = {};

			fs.readdir(
				process.cwd() + "/user_data/" + username + "/",
				(err: NodeJS.ErrnoException | null, files: string[]) => {
					res.status(200);
					res.send({ files: files });
				}
			);
		} catch (error) {
			res.status(400);
			res.send({ error: error });
		}
	})();
});

app.listen(port, () => {
	console.log(`[server] Server is listening on http://localhost:${port}`);
});
