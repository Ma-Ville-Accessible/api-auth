import { readFileSync } from 'fs';
import { join } from 'path';

import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as Crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as sgMail from '@sendgrid/mail';
import handlebars from 'handlebars';

import { HTTPError } from '../core/interfaces/Error';
import { User, UserDocument } from '../core/schemas/users.schema';

@Injectable()
export class UsersService {
  welcomeEmail = readFileSync(
    join(__dirname, '../assets/templates/welcome.handlebars'),
    'utf-8',
  );
  resetPasswordEmail = readFileSync(
    join(__dirname, '../assets/templates/forgottenPassword.handlebars'),
    'utf-8',
  );
  constructor(@InjectModel(User.name) private UserModel: Model<UserDocument>) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  }

  async getOneUser(id: string): Promise<object> {
    const User = await this.UserModel.findById(id);
    if (!User) {
      throw new HttpException('Not found', HttpStatus.NOT_FOUND);
    }
    return {
      id: User._id,
      email: User.email,
      firstName: User.firstName,
      lastName: User.lastName,
    };
  }

  private async authWithPassword(UserData: any): Promise<HTTPError | object> {
    const user = await this.UserModel.findOne({ email: UserData.email });
    if (!user) {
      throw new HttpException('Not found', HttpStatus.NOT_FOUND);
    }
    const isPasswordValid = await bcrypt.compare(
      UserData.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new HttpException('Wrong credentials', HttpStatus.FORBIDDEN);
    }

    return {
      accessToken: jwt.sign(
        { id: user._id, email: user.email },
        process.env.privateKey,
        { expiresIn: '900s' },
      ),
      tokenType: 'Bearer',
      expiresIn: 900,
      refreshToken: user.refreshToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    };
  }

  private async authWithRefreshToken(
    UserData: any,
  ): Promise<HTTPError | object> {
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
        { id: user._id, email: user.email },
        process.env.privateKey,
        { expiresIn: '900s' },
      ),
      tokenType: 'Bearer',
      expiresIn: 900,
      refreshToken: user.refreshToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    };
  }

  async createUser(User: User): Promise<HTTPError | any> {
    const user = await this.UserModel.findOne({ email: User.email });
    if (user) {
      throw new HttpException('User already exists', HttpStatus.CONFLICT);
    }
    if (!User.firstName || !User.lastName || !User.email || !User.password) {
      throw new HttpException('Missing fields', HttpStatus.BAD_REQUEST);
    }
    const cryptedPassword = await bcrypt.hash(User.password, 10);
    const newUser = new this.UserModel({
      ...User,
      password: cryptedPassword,
      refreshToken: Crypto.randomBytes(64).toString('hex'),
    });
    await newUser.save();

    const template = handlebars.compile(this.welcomeEmail);

    sgMail.send({
      to: user.email, // Change to your recipient
      from: {
        email: 'noreply@defless.fr', // Change to your verified sender
        name: 'Ma ville accessible',
      },
      subject: 'Bienvenue !',
      html: template({}),
    });

    //replace with simple response later
    return {
      accessToken: jwt.sign(
        { id: newUser._id, email: newUser.email },
        process.env.privateKey,
        { expiresIn: '900s' },
      ),
      tokenType: 'Bearer',
      expiresIn: 900,
      refreshToken: newUser.refreshToken,
    };
  }

  async signIn(UserData: any): Promise<HTTPError | object> {
    if (!UserData?.grantType) {
      throw new HttpException('Missing grantType', HttpStatus.BAD_REQUEST);
    }
    switch (UserData.grantType) {
      case 'password':
        return this.authWithPassword(UserData);
      case 'refreshToken':
        return this.authWithRefreshToken(UserData);
      default:
        throw new HttpException('Incorrect grant type', HttpStatus.BAD_REQUEST);
    }
  }

  async updateUser(id: string, User: User): Promise<HTTPError | User> {
    const storedUser = await this.UserModel.findById(id);
    storedUser.lastName = User.lastName;
    storedUser.firstName = User.firstName;
    if (User.password) {
      const isPasswordValid = await bcrypt.compare(
        User.password,
        storedUser.password,
      );
      if (!isPasswordValid) {
        throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
      }
      storedUser.password = await bcrypt.hash(User.password, 10);
    }
    return await storedUser.save();
  }

  async requestPasswordReset(data: object): Promise<HTTPError | object> {
    const user = await this.UserModel.findOne({ email: data['email'] });
    if (!user) {
      throw new HttpException('Not found', HttpStatus.NOT_FOUND);
    }
    user.otaCode = Crypto.randomBytes(64).toString('hex');

    const template = handlebars.compile(this.resetPasswordEmail);

    sgMail.send({
      to: user.email, // Change to your recipient
      from: {
        email: 'noreply@defless.fr', // Change to your verified sender
        name: 'Ma ville accessible',
      },
      subject: 'Réinitialisation de votre mot de passe',
      html: template({
        url: `http://localhost:3000/reset-password?ota=${user.otaCode}&userId=${user._id}`,
        firstName: user.firstName,
      }),
    });

    await user.save();
    return { message: 'Password reset requested' };
  }

  async updateUserPassword(
    id: string,
    data: object,
  ): Promise<HTTPError | object> {
    const user = await this.UserModel.findById(id);
    if (data['password'] !== data['passwordRepeat']) {
      throw new HttpException('password_mismatch', HttpStatus.BAD_REQUEST);
    }
    user.password = await bcrypt.hash(data['password'], 10);
    await user.save();
    return { message: 'Password updated' };
  }
}
