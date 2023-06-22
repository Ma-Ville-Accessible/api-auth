import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class PasswordChangeDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(8, {
    message: 'Password is too short',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, {
    message: 'PasswordRepeat is too short',
  })
  passwordRepeat: string;
}
