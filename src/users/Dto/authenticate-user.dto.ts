import { IsNotEmpty, IsString, IsEmail } from 'class-validator';

export class AuthenticateUserDto {
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  grantType: string;
}
