import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { User, UserDocument } from '../schemas/users.schema';
import * as jwt from 'jsonwebtoken';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(@InjectModel(User.name) private UserModel: Model<UserDocument>) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    return this.validateRequest(request);
  }

  private validateRequest = async (req: any): Promise<boolean> => {
    try {
      if (!req.headers.authorization) {
        throw new HttpException(
          'Missing authorization header',
          HttpStatus.BAD_REQUEST,
        );
      }
      const token = req.headers.authorization.split(' ')[1];
      const userId = jwt.verify(token, process.env.PRIVATE_KEY).id;
      const user = await this.UserModel.findById(userId);
      if (!user.isVerified) {
        throw new HttpException(
          'Unauthorized request',
          HttpStatus.UNAUTHORIZED,
        );
      }

      req.user = user;
      return true;
    } catch (error) {
      throw new HttpException('Unauthorized request', HttpStatus.UNAUTHORIZED);
    }
  };
}
