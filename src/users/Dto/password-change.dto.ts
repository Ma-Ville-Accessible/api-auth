import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class PasswordChangeDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(8, {
    message: 'password is too short',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, {
    message: 'passwordRepeat is too short',
  })
  passwordRepeat: string;
}
