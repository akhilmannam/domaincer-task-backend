//importing dependencies
const cors = require("cors");
const express = require("express");
const mongodb = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3001;

//Database variables
const URL = process.env.DB;
const DB = "portal";

app.use(cors());
app.use(express.json());

//Candidate or Recruiter SignUp
app.post("/register", async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		let salt = await bcrypt.genSalt(10);
		let hash = await bcrypt.hash(req.body.password, salt);
		req.body.password = hash;
		let response = await db.collection("users").insertOne(req.body);
		await db
			.collection("applied")
			.insertOne({ userID: response.ops[0]._id.toString(), applied: [] });
		res.json({
			message: "User Registered",
		});
	} catch (error) {
		console.log(error);
	}
});

//Login for both
app.post("/login", async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		let user = await db
			.collection("users")
			.findOne({ email: req.body.email });
		if (user) {
			let isPasswordCorrect = await bcrypt.compare(
				req.body.password,
				user.password
			);
			if (isPasswordCorrect) {
				let token = jwt.sign(
					{ _id: user._id, role: user.role },
					process.env.SECRET
				);
				res.json({
					message: "Allow",
					token: token,
					id: user._id,
					name: user.name,
					role: user.role,
				});
			} else {
				res.json({
					message: "Email or Password is incorrect",
				});
			}
		} else {
			res.json({
				message: "Email or Password is incorrect",
			});
		}
	} catch (error) {
		console.log(error);
	}
});

//Authentication middleware
function authenticate(req, res, next) {
	if (req.headers.authorization) {
		try {
			let jwtValid = jwt.verify(
				req.headers.authorization,
				process.env.SECRET
			);
			if (jwtValid) {
				req.userID = jwtValid._id;
				next();
			}
		} catch (error) {
			res.status(401).json({
				message: "Invalid Token",
			});
		}
	} else {
		res.status(401).json({
			message: "No Token Present",
		});
	}
}

//Post jobs by recruiter to common collection
app.post("/jobs", authenticate, async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		await db.collection("jobs").insertOne(req.body);
		await connection.close();
		res.json({
			message: "Job Posted",
		});
	} catch (error) {
		console.log(error);
	}
});

//Retrieve all jobs to be displayed to candidate
app.get("/jobs", authenticate, async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		let response = await db.collection("jobs").find().toArray();
		await connection.close();
		res.json(response);
	} catch (error) {
		console.log(error);
	}
});

//endpoint for posting applications to common collection
app.post("/applications", async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		await db.collection("applications").insertOne(req.body);
		await connection.close();
		res.json({
			message: "Application sent",
		});
	} catch (error) {
		console.log(error);
	}
});

//endpoint for getting applications for jobs posted by a recruiter
app.get("/applications/:id", authenticate, async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		let response = await db
			.collection("applications")
			.find({ recruiterID: req.params.id })
			.toArray();
		await connection.close();
		res.json(response);
	} catch (error) {
		console.log(error);
	}
});

app.post("/applied/:id", async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		await db
			.collection("applied")
			.updateOne(
				{ userID: req.body.userID },
				{ $set: { applied: req.body.applied } }
			);
		await connection.close();
		res.json({
			message: "Application sent",
		});
	} catch (error) {
		console.log(error);
	}
});

app.get("/applied/:id", async (req, res) => {
	try {
		let connection = await mongodb.connect(URL, {
			useUnifiedTopology: true,
		});
		let db = connection.db(DB);
		let response = await db
			.collection("applied")
			.findOne({ userID: req.params.id });
		await connection.close();
		res.json(response);
	} catch (error) {
		console.log(error);
	}
});

//Listening on port
app.listen(port);
