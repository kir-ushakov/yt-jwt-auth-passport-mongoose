import { Strategy as JwtStrategy } from 'passport-jwt';
import UserModel from '../database/mongodb/user.model';

interface IJwtTokenPayload {
  userDto: {
    firstName: string;
    lastName: string;
    email: string;
    userId: string;
  };
  iat: number;
  exp: number;
}

/**
 * #NOTE
 * Custom extractor to extract token from cookies
 */
const cookieExtractor = function (req) {
  var token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
  }
  return token;
};

/**
 * #NOTE
 * Pass the custom extractor
 * and the secret string from environment variables
 * as options
 */
const opts = {
  jwtFromRequest: cookieExtractor,
  secretOrKey: process.env.JWT_SECRET,
};

/**
 * #NOTE#
 * This Strategy will use as middle wasre for incoming reqests
 * to authenticate a user by jwt-token in cookies
 * and attach user object from DB to reqest (req.user)
 */
export const jwtStrategy = new JwtStrategy(opts, async function (
  jwtPayload: IJwtTokenPayload,
  done
) {
  try {
    /**
     * #NOTE#
     * Use userId from token payload to search in DB and return user object
     * this user object will be attached to request (req.user)
     */
    const user = await UserModel.findOne({ _id: jwtPayload.userDto.userId });
    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (err) {
    return done(err, false);
  }
});
