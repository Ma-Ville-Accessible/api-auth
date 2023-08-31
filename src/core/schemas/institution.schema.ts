import mongoose from 'mongoose';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { User } from './users.schema';

export type InstitutionDocument = HydratedDocument<Institution>;

@Schema()
export class Institution {
  @Prop({ unique: true, required: true })
  name: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  owner: User;

  @Prop({ unique: true })
  geoRef: number[];

  @Prop({ unique: true })
  apiKey: string;
}

export const InstitutionSchema = SchemaFactory.createForClass(Institution);
