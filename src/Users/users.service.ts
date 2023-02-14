import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import { User, UserDocument } from '../core/schemas/Users.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<UserDocument>,
  ) {}

  async getAllUsers(): Promise<User[]> {
    return await this.UserModel.find();
  }

  async getOneUser(id: string): Promise<User> {
    const User = await this.UserModel.findById(id);
    return User;
  }

  createUser(User: User): Promise<User> {
    const newUser = new this.UserModel(User);
    return newUser.save();
  }

  async updateUser(id: string, User: User): Promise<User> {
    const storedUser = await this.UserModel.findById(id);
    storedUser.title = User.title;
    storedUser.comment = User.comment;
    storedUser.location = User.location;
    return await storedUser.save();
  }

  async deleteUser(id: string): Promise<void> {
    return await this.UserModel.findByIdAndDelete(id);
  }
}
