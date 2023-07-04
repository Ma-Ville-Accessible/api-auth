import { IsEmail, IsNotEmpty, IsString, ValidateIf } from 'class-validator';

export class AuthenticateUserDto {
  @ValidateIf((o) => o.grantType === 'password')
  @IsString()
  @IsEmail()
  email?: string;

  @ValidateIf((o) => o.grantType === 'password')
  @IsString()
  @IsNotEmpty()
  password?: string;

  @ValidateIf((o) => o.grantType === 'refreshToken')
  @IsString()
  @IsNotEmpty()
  refreshToken?: string;

  @IsString()
  @IsNotEmpty()
  grantType: string;
}
