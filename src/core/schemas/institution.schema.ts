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
  reportId: User;

  @Prop({ unique: true })
  geoRef: string;

  @Prop({ unique: true })
  apiKey: string;
}

export const InstitutionSchema = SchemaFactory.createForClass(Institution);
