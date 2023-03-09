import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  UseGuards,
  HttpCode,
} from '@nestjs/common';

import { AuthGuard } from 'src/core/guards/auth.guard';
import { HTTPError } from '../core/interfaces/Error';
import { User } from '../core/schemas/users.schema';
//eslint-disable-next-line
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly UsersService: UsersService) {}

  @UseGuards(AuthGuard)
  @Get(':id')
  getUser(@Param('id') id: string): Promise<object> {
    return this.UsersService.getOneUser(id);
  }

  @Post()
  createUser(@Body() User: User): Promise<HTTPError | User> {
    return this.UsersService.createUser(User);
  }

  @HttpCode(200)
  @Post('authenticate')
  signIn(@Body() UserData: object): Promise<HTTPError | object> {
    return this.UsersService.signIn(UserData);
  }

  @UseGuards(AuthGuard)
  @Patch(':id')
  updateUser(
    @Param('id') id: string,
    @Body() User: User,
  ): Promise<HTTPError | User> {
    return this.UsersService.updateUser(id, User);
  }
}
