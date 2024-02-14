import passport from 'passport';
import { EAppError } from '../../core/app-error';
import { EHttpStatus } from '../http/models/base-controller';
import { IApiErrorDto } from '../http/dtos/api-errors.dto';

/**
 * #NOTE
 * This is an middleware method of checking user authentication.
 * */
export function isAuthenticated(req, res, next) {
  // Selecting strategy of authentication depending on
  // environment variable AUTHENTICATION_STRATEGY
  // In this case we only consider “JWT”
  // So please ignore session-based
  switch (process.env.AUTHENTICATION_STRATEGY) {
    case 'JWT':
      /**
       * #NOTE
       * Here we say "passport" to use the jwt strategy to process requests.
       */
      passport.authenticate('jwt', { session: false }, async (error, user) => {
        if (error || !user) {
          const errorDto: IApiErrorDto = {
            name: EAppError.UserNotAuthenticated,
            message: 'User not authenticated',
          };
          return res.status(EHttpStatus.Unauthorized).send(errorDto);
        }
        /**
         * #NOTE
         * Attach the user object to the request,
         * it can be use later on next stages of processing
         */
        req.user = user;
        next();
      })(req, res, next);
      break;

    // Don't care about this block - it's all about session-based authentication.
    case 'SESSION':
      if (req.isAuthenticated()) {
        return next();
      } else {
        const errorDto: IApiErrorDto = {
          name: EAppError.UnexpectedError,
          message: 'User not authenticated',
        };
        return res.status(401).send(errorDto);
      }
    default:
      throw new Error(
        `Not Supported Auth Strategy: ${process.env.AUTHENTICATION_STRATEGY}`
      );
  }
}
