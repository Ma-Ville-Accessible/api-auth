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
import { Throttle } from '@nestjs/throttler';

import { AuthGuard } from 'src/core/guards/auth.guard';
import { OtaGuard } from 'src/core/guards/ota.guard';
import { HTTPError } from '../core/interfaces/Error';
import { User } from '../core/schemas/users.schema';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { UpdateUserDto } from './Dto/update-user.dto';
import { ForgottenPasswordDto } from './Dto/forgotten-password.dto';
import { PasswordChangeDto } from './Dto/password-change.dto';
import { CreateUserDto } from './Dto/create-user.dto';
import { AuthenticateUserDto } from './Dto/authenticate-user.dto';
import { createExample } from '../swagger/users/create.example';
import { updateExample } from '../swagger/users/update.example';
import { authenticateExample } from '../swagger/users/authenticate.example';
import { UsersService } from './users.service';
import { validateBody } from 'src/core/utils/validation';

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
  async createUser(@Body() body: CreateUserDto): Promise<HTTPError | any> {
    const user: CreateUserDto = await validateBody(body, CreateUserDto);
    return this.usersService.createUser(user);
  }

  @HttpCode(200)
  @Throttle(10, 60)
  @Post('authenticate')
  @ApiOperation({ summary: 'Authenticate user' })
  @ApiBody({
    description: 'Authenticate user',
    type: AuthenticateUserDto,
    examples: {
      example: authenticateExample,
    },
  })
  async signIn(@Body() body: AuthenticateUserDto): Promise<HTTPError | any> {
    const data = await validateBody(body, AuthenticateUserDto);
    return this.usersService.signIn(data);
  }

  @UseGuards(AuthGuard)
  @Patch(':id')
  @ApiOperation({ summary: 'Update user' })
  @ApiBody({
    description: 'Update user',
    type: UpdateUserDto,
    examples: {
      example: updateExample,
    },
  })
  async updateUser(
    @Param('id') id: string,
    @Body() body: UpdateUserDto,
  ): Promise<HTTPError | User> {
    const data = await validateBody(body, UpdateUserDto);
    return this.usersService.updateUser(id, data);
  }

  @Post('password')
  @ApiOperation({ summary: 'Forgotten password' })
  @ApiBody({
    description: 'send forgotten password request',
    type: ForgottenPasswordDto,
    examples: {
      example: {
        value: { email: 'test@email.com ' },
      },
    },
  })
  async requestPasswordReset(
    @Body() body: ForgottenPasswordDto,
  ): Promise<HTTPError | any> {
    const data = await validateBody(body, ForgottenPasswordDto);
    return this.usersService.requestPasswordReset(data);
  }

  @UseGuards(OtaGuard)
  @Put(':id/password')
  @ApiOperation({ summary: 'Password change' })
  @ApiBody({
    description: 'Change user password',
    type: PasswordChangeDto,
    examples: {
      example: {
        value: {
          password: 'strongPassword',
          passwordRepeat: 'strongPassword',
        },
      },
    },
  })
  async updateUserPassword(
    @Param('id') id: string,
    @Body() body: PasswordChangeDto,
  ): Promise<HTTPError | any> {
    const data = await validateBody(body, PasswordChangeDto);
    return this.usersService.updateUserPassword(id, data);
  }

  @UseGuards(OtaGuard)
  @Get(':id/validate')
  // create return message type
  verifyUser(@Param('id') id: string): Promise<HTTPError | any> {
    return this.usersService.verifyUser(id);
  }
}
