import { IsNotEmpty, IsString } from 'class-validator';

export class PasswordChangeDto {
  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  passwordRepeat: string;
}
