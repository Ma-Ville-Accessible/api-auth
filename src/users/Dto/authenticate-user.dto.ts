import { IsNotEmpty, IsString } from 'class-validator';

export class AuthenticateUserDto {
  @IsString()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  grantType: string;
}
