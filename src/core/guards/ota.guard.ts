import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../schemas/users.schema';

@Injectable()
export class OtaGuard implements CanActivate {
  constructor(@InjectModel(User.name) private UserModel: Model<UserDocument>) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    return this.validateRequest(request);
  }

  private validateRequest = async (req): Promise<boolean> => {
    try {
      if (!req.headers.authorization) {
        throw new HttpException(
          'Missing authorization header',
          HttpStatus.BAD_REQUEST,
        );
      }
      const otaCode = req.headers.authorization.split(' ')[1];
      const userId = req.params.id;
      const user = await this.UserModel.findOne({ _id: userId });
      if (!user.otaCode || user.otaCode !== otaCode) {
        user.otaCode = null;
        await user.save();
        throw new HttpException(
          'Unauthorized request',
          HttpStatus.UNAUTHORIZED,
        );
      } else {
        return true;
      }
    } catch (error) {
      throw new HttpException('Unauthorized request', HttpStatus.UNAUTHORIZED);
    }
  };
}
