import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  UseGuards,
  Put,
} from '@nestjs/common';

import { AuthGuard } from 'src/core/guards/auth.guard';
import { OtaGuard } from 'src/core/guards/ota.guard';
import { HTTPError } from '../core/interfaces/Error';
import { User } from '../core/schemas/users.schema';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { UpdateUserDto } from './Dto/update-user.dto';
import { CreateUserDto } from './Dto/create-user.dto';
import { AuthenticateUserDto } from './Dto/authenticate-user.dto';
import { createExample } from '../swagger/users/create.example';
import { updateExample } from '../swagger/users/update.example';
import { authenticateExample } from '../swagger/users/authenticate.example';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(AuthGuard)
  @Get(':id')
  getUser(@Param('id') id: string): Promise<object> {
    return this.usersService.getOneUser(id);
  }

  @Post()
  @ApiOperation({ summary: 'Create category' })
  @ApiBody({
    description: 'Create user',
    type: CreateUserDto,
    examples: {
      example: createExample,
    },
  })
  createUser(@Body() User: User): Promise<HTTPError | User> {
    return this.usersService.createUser(User);
  }

  @HttpCode(200)
  @Post('authenticate')
  @ApiOperation({ summary: 'Authenticate user' })
  @ApiBody({
    description: 'Authenticate user',
    type: AuthenticateUserDto,
    examples: {
      example: authenticateExample,
    },
  })
  signIn(@Body() UserData: object): Promise<HTTPError | object> {
    return this.usersService.signIn(UserData);
  }

  @UseGuards(AuthGuard)
  @Patch(':id')
  @ApiOperation({ summary: 'Update category' })
  @ApiBody({
    description: 'Update category',
    type: UpdateUserDto,
    examples: {
      example: updateExample,
    },
  })
  updateUser(
    @Param('id') id: string,
    @Body() User: User,
  ): Promise<HTTPError | User> {
    return this.usersService.updateUser(id, User);
  }

  @Post('password')
  requestPasswordReset(@Body() data: object): Promise<HTTPError | object> {
    return this.usersService.requestPasswordReset(data);
  }

  @UseGuards(OtaGuard)
  @Put(':id/password')
  updateUserPassword(
    @Param('id') id: string,
    @Body() data: object,
  ): Promise<HTTPError | object> {
    return this.usersService.updateUserPassword(id, data);
  }
}
