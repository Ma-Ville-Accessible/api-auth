import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
  @Prop()
  title: string;

  @Prop()
  comment: string;

  @Prop({ type: Object })
  location: object;
}

export const UserSchema = SchemaFactory.createForClass(User);
