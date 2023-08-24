import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  isAlive(): string {
    return 'Ma Ville Accessible - Auth_api';
  }
}
