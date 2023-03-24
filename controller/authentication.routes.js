const express = require("express");
const authRoutes = express.Router();
const bcrypt = require("bcrypt");
const { model } = require("../model/authModel");
const { tokenR } = require("../auth&auth/jwt");


authRoutes.post("/register", async (req, res) => {
    const { username, email, dob, password } = req.body;
    const preCheck = await model.findOne({ $or: [{ username }, { email }] });
    if (username && email && dob && password) {
        if (!preCheck) {
            try {
                const hashPass = await bcrypt.hash(password, 12);
                const userData = new model({ username, email, dob, password: hashPass });
                await userData.save();
                res.send({ msg: "success" });
            } catch (e) {
                res.send({ msg: e.message });
            }
        } else {
            res.send({ msg: "user already present" });
        }
    } else {
        res.send({ msg: "Invalid format" });
    }
})

authRoutes.post("/login", async (req, res) => {
    const { username, email, password } = req.body;
    if ((username && password) || (email && password)) {
        try {
            const loginCheck = await model.findOne({ $or: [{ username }, { email }] });
            // User check
            if (loginCheck) {
                const token = tokenR(loginCheck.role);
                const compare = await bcrypt.compare(password, loginCheck.password);
                if (compare) {
                    res.send({ status: "success", msg: "login success", token });
                } else {
                    res.send({ msg: "invalid password" });
                }
            } else {
                res.status(404).send({ msg: "user not found" });
            }
        } catch (e) {
            res.send({ msg: e.message });
        }
    } else {
        res.send({ msg: "data type not found" });
    }
})


module.exports = { authRoutes };