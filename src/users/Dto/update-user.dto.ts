import { ValidateIf, IsOptional, IsString, IsNotEmpty } from 'class-validator';

export class UpdateUserDto {
  @IsString()
  @IsOptional()
  firstName?: string;

  @IsString()
  @IsOptional()
  lastName?: string;

  @ValidateIf((o) => !!o.newPassword)
  @IsString()
  @IsNotEmpty()
  oldPassword?: string;

  @ValidateIf((o) => !!o.oldPassword)
  @IsString()
  @IsNotEmpty()
  newPassword?: string;

  @ValidateIf((o) => !!o.newPassword)
  @IsString()
  @IsNotEmpty()
  newPasswordRepeat?: string;
}
