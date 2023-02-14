import {
  Controller,
  Get,
  Post,
  Delete,
  Patch,
  Body,
  Param,
} from '@nestjs/common';

import { User } from '../core/schemas/Users.schema';
import { UsersService } from './Users.service';

@Controller('Users')
export class UsersController {
  constructor(private readonly UserService: UsersService) {}

  @Get()
  getUsers(): Promise<User[]> {
    return this.UserService.getAllUsers();
  }

  @Get(':id')
  getUser(@Param('id') id: string): Promise<User> {
    return this.UserService.getOneUser(id);
  }

  @Post()
  createUser(@Body() User: User): Promise<User> {
    return this.UserService.createUser(User);
  }

  @Patch(':id')
  updateUser(
    @Param('id') id: string,
    @Body() User: User,
  ): Promise<User> {
    return this.UserService.updateUser(id, User);
  }

  @Delete(':id')
  async deleteUser(@Param('id') id: string): Promise<object> {
    try {
      await this.UserService.deleteUser(id);
      return { success: true };
    } catch (error) {
      return { success: false };
    }
  }
}
