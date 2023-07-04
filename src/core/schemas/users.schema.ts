import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
  @Prop({ required: true })
  firstName: string;

  @Prop({ required: true })
  lastName: string;

  @Prop({ required: false })
  image: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ unique: true })
  refreshToken: string;

  @Prop({ unique: true })
  otaCode: string;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop()
  usedRefresh: [string];
}

export const UserSchema = SchemaFactory.createForClass(User);
