import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as Crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';

import { HTTPError } from '../core/interfaces/Error';
import { User, UserDocument } from '../core/schemas/users.schema';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private UserModel: Model<UserDocument>) {}

  async getOneUser(id: string): Promise<User> {
    const User = await this.UserModel.findById(id);
    if (!User) {
      throw new HttpException('Not found', HttpStatus.NOT_FOUND);
    }
    return User;
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
      access_token: jwt.sign(
        { id: user._id, email: user.email },
        process.env.privateKey,
        { expiresIn: '900s' },
      ),
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: user.refreshToken,
    };
  }

  private async authWithRefreshToken(
    UserData: any,
  ): Promise<HTTPError | object> {
    const user = await this.UserModel.findById(UserData.id);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    if (user.refreshToken !== UserData.refresh_token) {
      throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
    }
    user.refreshToken = Crypto.randomBytes(64).toString('hex');
    await user.save();
    return {
      access_token: jwt.sign(
        { id: user._id, email: user.email },
        process.env.privateKey,
        { expiresIn: '900s' },
      ),
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: user.refreshToken,
    };
  }

  async createUser(User: User): Promise<HTTPError | any> {
    const user = await this.UserModel.findOne({ email: User.email });
    if (user) {
      throw new HttpException('User already exists', HttpStatus.CONFLICT);
    }
    const cryptedPassword = await bcrypt.hash(User.password, 10);
    const newUser = new this.UserModel({
      ...User,
      password: cryptedPassword,
      refresh_token: Crypto.randomBytes(64).toString('hex'),
    });
    await newUser.save();

    return {
      access_token: jwt.sign(
        { id: newUser._id, email: newUser.email },
        process.env.privateKey,
        { expiresIn: '900s' },
      ),
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: newUser.refreshToken,
    };
  }

  async signIn(UserData: any): Promise<HTTPError | object> {
    if (!UserData?.grant_type) {
      throw new HttpException('Missing grantType', HttpStatus.BAD_REQUEST);
    }
    switch (UserData.grant_type) {
      case 'password':
        return this.authWithPassword(UserData);
      case 'refresh_token':
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

  async deleteUser(id: string): Promise<void> {
    return await this.UserModel.findByIdAndDelete(id);
  }
}
