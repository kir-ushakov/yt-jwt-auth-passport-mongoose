import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import {
  BaseController,
  EHttpStatus,
} from '../../../../shared/infra/http/models/base-controller';
import { PassportStatic } from 'passport';
import { LoginResponseDTO } from './login.dto';
import { UserPersistent } from '../../../../shared/domain/models/user';
import { IUserDto } from '../../dto/user.dto';
import { EApiErrorType } from '../../../../shared/infra/http/models/api-error-types.enum';

export class LoginController extends BaseController {
  private _passport: PassportStatic;

  constructor(passport: PassportStatic) {
    super();
    this._passport = passport;
  }

  protected async executeImpl(
    req: Request,
    res: Response,
    next?: NextFunction
  ): Promise<void | any> {
    try {
      /**
       * #NOTE
       * We process the login request using the "local" strategy
       * and get the user object as a result.
       */
      this._passport.authenticate('local', (err, user: UserPersistent) => {
        if (err) {
          return this.fail(res, err);
        }

        if (!user) {
          return BaseController.jsonResponse(res, EHttpStatus.Unauthorized, {
            name: EApiErrorType.AUTHENTICATION_FAILED,
            message: 'Authorization failed!',
          });
        }

        if (!user.verified) {
          return BaseController.jsonResponse(res, EHttpStatus.Unauthorized, {
            name: EApiErrorType.USER_ACCOUNT_NOT_VERIFIED,
            message: 'User account not verified!',
          });
        }

        const userDto: IUserDto = {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.username,
          userId: user._id,
        };
        const loginResponseDto: LoginResponseDTO = { userDto: userDto };

        // Don't care about this block - it's all about session-based authentication.
        if (process.env.AUTHENTICATION_STRATEGY === 'SESSION') {
          req.logIn(user, (err) => {
            if (err) {
              return this.fail(res, err);
            }
            return this.ok(res, loginResponseDto);
          });
        }

        if (process.env.AUTHENTICATION_STRATEGY === 'JWT') {
          const expiresIn = 60 * 60;
          /**
           * #NOTE
           * jwt.sign()
           * - build json object with header and payload
           * - signing the payload and header with the secret key JWT_SECRET from env variables
           * - convert json to Base64URL encoded format and attach signature
           * Result looks like this:
           * 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyRHRvIjp7ImZpcnN0TmFtZSI6IktpciIsImxhc
           * 3ROYW1lIjoiVXNoYWtvdiIsImVtYWlsIjoia2l0dXNoYWtvZmZAZ21haWwuY29tIiwidXNlcklkIjoiNjU
           * 3ZWQ3OTg5NDAzNWIwOGJiODAxMjA4In0sImlhdCI6MTcwNzc0MDcyNSwiZXhwIjoxNzA3NzQ0MzI1fQ.ob
           * jvXNh_DflJUl7iIEmK9M2AMn_EOR9HDIVShn0HZMw'
           */
          const newToken = jwt.sign(loginResponseDto, process.env.JWT_SECRET, {
            expiresIn: expiresIn,
          });

          /**
           * #NOTE
           * Set token in cookies
           */
          res.cookie('jwt', newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            expires: new Date(new Date().getTime() + expiresIn * 1000),
          });

          return this.ok(res, loginResponseDto);
        }
      })(req, res, next);
    } catch (err) {
      return this.fail(res, err.toString());
    }
  }
}
