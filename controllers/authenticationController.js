    const User = require('../models/User');
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const { check, validationResult } = require('express-validator');

    exports.home = async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array() });
        }
        res.status(200).render('home', { message: 'Welcome to my first Middleware REST API!' });
    }

    exports.register = async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array() });
        }
        res.status(200).render('signUp', { pageTitle: 'Sign Up Form' });
    }

    exports.signup = async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array() });
        }
        // create user
        const { name, email, password, confirmPassword } = req.body;
        try {
            User.create({
                name: name,
                password: password,
                email: email,
                confirmPassword: confirmPassword
            }).then(user => res.json(user));
        } catch (error) {
            console.log(error);
            const errors = validationResult(req);
            const errorDetails = [
                {
                    "location": "Authorization",
                    "msg": `${name} ${error}`,
                    "param": name
                }
            ];
            res.json({errors: errorDetails});
        }
    }

    exports.loginForm = async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array() });
        }
        res.status(200).render('login', { pageTitle: 'Login Form' });
    }

    exports.login = async (req, res) => {

    
        const user = await User.findOne({ email: req.body.email });

        if(!user) {
            return res.status(401).render('home', { message: `<<Error>> login unsuccessful invalid credentials` });
        }
        
        const isMatch = await bcrypt.compare(req.body.password, user.password);
        if(!isMatch) {
            return res.status(401).render('home', { message: `<<Error>> user: ${user.name} unsuccessful login` });
        }
        try {
            let token = await user.generateAuthToken();
            res.cookie('jstoken', token, {
                expires: new Date(Date.now() + 25892000000),
                httpOnly: true
            });
            return res.status(200).render('home', { message: `user: ${user.name} login successful` });
        } catch (error) {
            console.log(error);
            return res.status(401).render('home', { message: `user: ${user.name} error: ${error} login unsuccessful` });
        }
    }

    exports.logout = async (req, res) => {
        try {
            req.user.tokens = req.user.tokens.filter((currentElement) => {
                return currentElement.token !== req.token;
            });
            res.clearCookie('jwtoken', { path: '/' });
            await req.user.save();
            res.status(200).send('User logout');
        } catch (error) {
            console.log(error);
        }
    }
