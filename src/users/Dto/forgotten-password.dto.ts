import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class ForgottenPasswordDto {
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
