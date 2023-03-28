    // set environment variables
    const dotenv = require('dotenv');
    dotenv.config({path: './config.env'});

    // template for node.js express server
    const express = require('express');
    // create express app
    const app = express();
    // body-parser is a middleware that parses incoming requests with json payloads
    const bodyParser = require('body-parser');
    app.use(bodyParser.urlencoded({ extended: false }));

    // path module provides utilities for working with file and dir paths
    const path = require('path');

    // __dirname is the directory name of the current module
    app.use(express.static(path.join(__dirname, 'public')));

    // set the view engine to ejs
    app.set('view engine', 'ejs');
    // set the views directory
    app.set('views', 'views');

    // routes defined in the routes folder
    const authenticationRoute = require('./routes/authenticationRoute');
    app.use('/api', authenticationRoute);

    // 404 error page
    app.use((err, req, res, next) => {
        res.status(40).render('404', { pageTitle: 'Page Not Found'});
    });

    // connecting to the database
    const mongoose = require('mongoose');

    // asynchronous connection
    mongoose.connect('mongodb+srv://asuift458:asu1234@cluster0.qopgnyc.mongodb.net/demodb', {useNewUrlParser: true})
        .then(() => console.log('MongoDB connection successful'))
        .catch((err) => console.error(err));

    // start the server
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`App running on port ${port}...`)
    });