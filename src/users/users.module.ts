import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { User, UserSchema } from '../core/schemas/users.schema';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import {
  Institution,
  InstitutionSchema,
} from 'src/core/schemas/institution.schema';

@Module({
  imports: [
    ConfigModule.forRoot(),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Institution.name, schema: InstitutionSchema },
    ]),
    ThrottlerModule.forRoot(),
  ],
  controllers: [UsersController],
  providers: [
    UsersService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class UsersModule {}
