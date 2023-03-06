import {
  Controller,
  Get,
  Post,
  Delete,
  Patch,
  Body,
  Param,
} from '@nestjs/common';

import { HTTPError } from '../core/interfaces/Error';
import { User } from '../core/schemas/Users.schema';
//eslint-disable-next-line
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly UsersService: UsersService) {}

  @Get(':id')
  getUser(@Param('id') id: string): Promise<User> {
    return this.UsersService.getOneUser(id);
  }

  @Post()
  createUser(@Body() User: User): Promise<HTTPError | User> {
    return this.UsersService.createUser(User);
  }

  @Post('authenticate')
  signIn(@Body() UserData: object): Promise<HTTPError | object> {
    return this.UsersService.signIn(UserData);
  }

  @Patch(':id')
  updateUser(
    @Param('id') id: string,
    @Body() User: User,
  ): Promise<HTTPError | User> {
    return this.UsersService.updateUser(id, User);
  }

  @Delete(':id')
  async deleteUser(@Param('id') id: string): Promise<object> {
    try {
      await this.UsersService.deleteUser(id);
      return { success: true };
    } catch (error) {
      return { success: false };
    }
  }
}
