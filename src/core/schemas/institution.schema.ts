import mongoose, { HydratedDocument } from 'mongoose';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { User } from './users.schema';

export type InstitutionDocument = HydratedDocument<Institution>;

@Schema()
export class Institution {
  @Prop({ unique: true, required: true })
  name: string;

  @Prop({ unique: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  owner: User;

  @Prop({ unique: true })
  geoRef: number[];

  @Prop({ unique: true })
  apiKey: string;
}

export const InstitutionSchema = SchemaFactory.createForClass(Institution);
