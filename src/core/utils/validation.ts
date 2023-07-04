import { HttpException, HttpStatus } from '@nestjs/common';
import { ClassConstructor, plainToClass } from 'class-transformer';
import { validate } from 'class-validator';

export class MultipleErrorsException extends HttpException {
  constructor(errors: any[]) {
    super({ errors }, HttpStatus.BAD_REQUEST);
  }
}

export const validateBody = async (
  body: object,
  dto: ClassConstructor<any>,
) => {
  const parsed = plainToClass(dto, body);
  const errors = await validate(parsed);

  if (errors.length > 0) {
    throw new MultipleErrorsException(
      errors.map((e) => ({
        field: e.property,
        errors: Object.values(e.constraints),
      })),
    );
  }

  return parsed;
};
