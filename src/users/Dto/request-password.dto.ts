import { IsNotEmpty, IsString } from 'class-validator';

export class RequestPasswordDto {
  @IsString()
  @IsNotEmpty()
  email: string;
}
