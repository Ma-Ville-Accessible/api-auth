import { IsNotEmpty, IsString, IsEmail } from 'class-validator';

export class ForgottenPasswordDto {
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
