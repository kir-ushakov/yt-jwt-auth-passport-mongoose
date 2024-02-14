import express from 'express';
import passport from 'passport';
import cookieParser from 'cookie-parser';
import { apiRouters } from './shared/infra/http/api';
import * as loaders from './loaders';
import UserModel from './shared/infra/database/mongodb/user.model';
import { jwtStrategy } from './shared/infra/auth/';

const cors = require('cors');

export const app = express();
app.use(cors());
app.use(express.json());

const secret = process.env.SESSION_SECRET;
const expressSession = require('express-session')({
  secret,
  resave: false,
  saveUninitialized: false,
});

app.use(expressSession);

loaders.bootstrap('Node Backend App');

/**
 * #NOTE
 * Initialize cookieParser to parse Cookie header and populate req.cookies
 */
app.use(cookieParser());

/**
 * #NOTE
 * Set 'local' Strategy that shipping with passport-local-mongoose plugin
 * This Strategy performs login/password authentication and retrieves the User object from the database.
 */
passport.use(UserModel.createStrategy());

// Don't care about this block - it's all about session-based authentication.
if (process.env.AUTHENTICATION_STRATEGY === 'SESSION') {
  app.use(passport.initialize());
  app.use(passport.session());
  passport.serializeUser(UserModel.serializeUser());
  passport.deserializeUser(UserModel.deserializeUser());
}

if (process.env.AUTHENTICATION_STRATEGY === 'JWT') {
  /**
   * #NOTE
   * Set JWT Strategy to process incoming request
   * and attaching user object to request (req.user) for authenticated user
   */
  passport.use(jwtStrategy);
}

app.use('/', apiRouters);
