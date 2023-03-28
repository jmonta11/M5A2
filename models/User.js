    const mongoose = require('mongoose');
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const config = require('config');
    const { check, validationResult } = require('express-validator');

    const UserSchema = new mongoose.Schema({
        name: {
            type: String,
            required: true,
            unique: true
        },
        email: {
            type: String,
            required: true,
            unique: true
        },
        password: {
            type: String,
            required: true
        },
        confirmPassword: {
            type: String,
            required: true,
            validate: {
                validator: function(el) {
                    return el === this.password;
                },
                message: 'Password are not the same!'
            }
        },
        date: {
            type: Date,
            default: Date.now
        }
    });

    UserSchema.pre('save', async function(next) {
        if(this.isModified('password')) {
            this.password = await bcrypt.hash(this.password, 10);
            this.confirmPassword = await bcrypt.hash(this.confirmPassword, 10);
            this.confirmPassword = undefined; // does not store in database
        }
        next();
    });

    UserSchema.methods.generateAuthToken = async function() {
        try {
            let token = jwt.sign({_id: this._id}, process.env.TOKEN_SECRET_KEY);
            
            return token;
        } catch (error) {
            console.log(error);
        }
    };

    UserSchema.methods.verifyPassword = async function(password) {
        const user = this;
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            throw new Error('Unable to login');
        }
    };

    UserSchema.statics.findByCredentials = async (email, password) => {
        const user = await UserSchema.findOne({ email });
        if (!user) {
            throw new Error('Unable to login');
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            throw new Error('Unable to login');
        }
        return user;
    }

    module.exports = mongoose.model('User', UserSchema)