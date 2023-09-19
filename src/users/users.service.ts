import { readFileSync } from 'fs';

import {
  HttpException,
  HttpStatus,
  Injectable,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as Crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import handlebars from 'handlebars';

import { send } from '../core/utils/mails';
import { User, UserDocument } from '../core/schemas/users.schema';
import { CreateUserDto } from './Dto/create-user.dto';
import { UpdateUserDto } from './Dto/update-user.dto';
import {
  Institution,
  InstitutionDocument,
} from '../core/schemas/institution.schema';
import {
  user,
  auth,
  create,
  update,
  verify,
  requestPassword,
  updatePassword,
} from './user.interface';

@Injectable()
export class UsersService {
  emailValidation = readFileSync(
    require.resolve('../../assets/templates/emailValidation.handlebars'),
    'utf-8',
  );
  resetPasswordEmail = readFileSync(
    require.resolve('../../assets/templates/forgottenPassword.handlebars'),
    'utf-8',
  );

  constructor(
    @InjectModel(User.name) private UserModel: Model<UserDocument>,
    @InjectModel(Institution.name)
    private InstitutionModel: Model<InstitutionDocument>,
  ) {}

  async getOneUser(id: string): Promise<user> {
    const User = await this.UserModel.findById(id);
    if (!User) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    return {
      id: User._id.toString(),
      email: User.email,
      firstName: User.firstName,
      lastName: User.lastName,
      isVerified: User.isVerified,
    };
  }

  private async authWithPassword(host: string, UserData: any): Promise<auth> {
    const user = await this.UserModel.findOne({ email: UserData.email });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    if (!user.isVerified) {
      throw new UnauthorizedException('User not verified');
    }

    const isPasswordValid = await bcrypt.compare(
      UserData.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
    }

    const institution = await this.InstitutionModel.findOne({
      owner: user,
    });

    if (host === process.env.DASHBOARD_URL && !institution) {
      throw new ForbiddenException('Unauthorized request');
    }

    return {
      accessToken: jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        process.env.PRIVATE_KEY,
        { expiresIn: '9000000s' },
      ),
      tokenType: 'Bearer',
      expiresIn: 9000000,
      refreshToken: user.refreshToken,
      user: {
        ...(institution && { institution }),
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified,
      },
    };
  }

  //could delegate this to the guard
  private async authWithRefreshToken(UserData: any): Promise<auth> {
    const user = await this.UserModel.findById(UserData.id);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    if (user.refreshToken !== UserData.refreshToken) {
      throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
    }
    user.usedRefresh.push(user.refreshToken);
    user.refreshToken = Crypto.randomBytes(64).toString('hex');
    await user.save();
    return {
      accessToken: jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        process.env.PRIVATE_KEY,
        { expiresIn: '9000000s' },
      ),
      tokenType: 'Bearer',
      expiresIn: 9000000,
      refreshToken: user.refreshToken,
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified,
      },
    };
  }

  async createUser(User: CreateUserDto): Promise<create> {
    const user = await this.UserModel.findOne({ email: User.email });
    if (user) {
      throw new HttpException('User already exists', HttpStatus.CONFLICT);
    }
    const cryptedPassword = await bcrypt.hash(User.password, 10);
    const newUser = await this.UserModel.create({
      ...User,
      password: cryptedPassword,
      otaCode: Crypto.randomBytes(64).toString('hex'),
      refreshToken: Crypto.randomBytes(64).toString('hex'),
    });

    await newUser.save();

    const template = handlebars.compile(this.emailValidation);

    await send(
      User.email,
      'Bienvenue !',
      template({
        url: `${process.env.VALIDATE_EMAIL_URL}?ota=${newUser.otaCode}&userId=${newUser._id}`,
        firstName: newUser.firstName,
      }),
    );

    //replace with simple response later
    return {
      accessToken: jwt.sign(
        { id: newUser._id, email: newUser.email },
        process.env.PRIVATE_KEY,
        { expiresIn: '9000000s' },
      ),
      tokenType: 'Bearer',
      expiresIn: 9000000,
      refreshToken: newUser.refreshToken,
    };
  }

  async signIn(host: string, UserData: any): Promise<auth> {
    switch (UserData.grantType) {
      case 'password':
        return this.authWithPassword(host, UserData);
      case 'refreshToken':
        return this.authWithRefreshToken(UserData);
      default:
        throw new HttpException('Incorrect grantType', HttpStatus.BAD_REQUEST);
    }
  }

  async updateUser(id: string, User: UpdateUserDto): Promise<update> {
    const storedUser = await this.UserModel.findById(id);
    if (!storedUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    if (User.oldPassword) {
      if (User.newPassword !== User.newPasswordRepeat) {
        throw new HttpException(
          'New password and confirmation do not match',
          HttpStatus.BAD_REQUEST,
        );
      }

      const isPasswordValid = await bcrypt.compare(
        User.oldPassword,
        storedUser.password,
      );

      if (!isPasswordValid) {
        throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
      }

      storedUser.password = await bcrypt.hash(User.newPassword, 10);
    }

    storedUser.lastName = User.lastName || storedUser.lastName;
    storedUser.firstName = User.firstName || storedUser.firstName;
    await storedUser.save();

    return {
      firstName: storedUser.firstName,
      lastName: storedUser.lastName,
    };
  }

  async requestPasswordReset(data: object): Promise<requestPassword> {
    const user = await this.UserModel.findOne({ email: data['email'] });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    user.otaCode = Crypto.randomBytes(64).toString('hex');

    const template = handlebars.compile(this.resetPasswordEmail);

    send(
      user.email,
      'Réinitialisation de votre mot de passe',
      template({
        url: `${process.env.LOST_PASSWORD_URL}?ota=${user.otaCode}&userId=${user._id}`,
        firstName: user.firstName,
      }),
    );

    await user.save();
    return { message: 'Password reset requested' };
  }

  async updateUserPassword(id: string, body: object): Promise<updatePassword> {
    const user = await this.UserModel.findById(id);
    if (body['password'] !== body['passwordRepeat']) {
      throw new HttpException('Passwords mismatch', HttpStatus.BAD_REQUEST);
    }
    user.password = await bcrypt.hash(body['password'], 10);
    user.otaCode = null;
    await user.save();
    return { message: 'Password updated' };
  }

  async verifyUser(id: string): Promise<verify> {
    const user = await this.UserModel.findById(id);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    user.isVerified = true;
    await user.save();
    return { message: 'User validated' };
  }
}
