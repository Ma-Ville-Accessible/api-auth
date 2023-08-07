import { Types } from 'mongoose';
import { getModelToken } from '@nestjs/mongoose';
import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import * as sgMail from '@sendgrid/mail';

import { User } from '../core/schemas/users.schema';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { isJWT } from 'class-validator';
describe('UsersController', () => {
  let usersController: UsersController;

  Object.assign(sgMail.send, jest.fn());
  const save = jest.fn();
  const mockedUserModel = {
    find: jest.fn(),
    findOne: jest.fn(),
    findById: jest.fn(),
    findByIdAndDelete: jest.fn(),
    create: jest.fn(),
  };

  const mockedUser = {
    _id: new Types.ObjectId().toString(),
    firstName: 'john',
    lastName: 'doe',
    email: 'john@doe.fr',
    isVerified: true,
    refreshToken: 'refreshToken',
    save,
  };

  jest.mock('@sendgrid/mail');

  process.env.PRIVATE_KEY = 'test';
  process.env.ENV = 'test';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        UsersService,
        { provide: getModelToken(User.name), useValue: mockedUserModel },
      ],
    }).compile();

    //UsersService = module.get<UsersService>(UsersService);
    usersController = module.get<UsersController>(UsersController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('get(:userId)', () => {
    it('should return specific user', async () => {
      mockedUserModel.findById.mockReturnValue(mockedUser);
      expect(await usersController.getUser(mockedUser._id)).toStrictEqual({
        id: mockedUser._id,
        firstName: 'john',
        lastName: 'doe',
        email: 'john@doe.fr',
        isVerified: true,
      });
      expect(mockedUserModel.findById).toHaveBeenCalledWith(mockedUser._id);
    });

    it('should return "Invalid ID" error', async () => {
      let error;
      try {
        await usersController.getUser('invalidId');
      } catch (e) {
        error = e;
      }
      expect(error).toStrictEqual(
        new HttpException('Invalid ID', HttpStatus.BAD_REQUEST),
      );
      expect(mockedUserModel.findById).toHaveBeenCalledTimes(0);
    });

    it('should return "User not found" error', async () => {
      mockedUserModel.findById.mockReturnValue(null);
      let error;
      try {
        await usersController.getUser(mockedUser._id);
      } catch (e) {
        error = e;
      }
      expect(error).toStrictEqual(
        new HttpException('User not found', HttpStatus.NOT_FOUND),
      );
      expect(mockedUserModel.findById).toHaveBeenCalledTimes(1);
    });
  });

  describe('createUser()', () => {
    it('should create a User', async () => {
      mockedUserModel.create.mockImplementationOnce(() => mockedUser);
      mockedUserModel.findOne.mockReturnValue(null);
      const request = await usersController.createUser({
        email: 'simon.deflesschouwer@mmibordeaux.com',
        password: 'password',
        firstName: 'test',
        lastName: 'test',
      });
      expect(request.accessToken).toBeTruthy();
      expect(isJWT(request.accessToken)).toBeTruthy();
      const tokenContent = jwt.verify(
        request.accessToken,
        process.env.PRIVATE_KEY,
      );
      expect(tokenContent.id).toBe(mockedUser._id);
      expect(request.refreshToken).toBe('refreshToken');
      //add test for sendgri email
    });

    it('should not create a User if it already exists', async () => {
      mockedUserModel.findOne.mockReturnValueOnce({ _id: 'existingUser' });
      let error;
      try {
        await usersController.createUser({
          email: 'simon.deflesschouwer@mmibordeaux.com',
          password: 'password',
          firstName: 'test',
          lastName: 'test',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('User already exists', HttpStatus.CONFLICT),
      );
    });

    it('should throw an error if params are missing', async () => {
      let error;
      try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore:
        await usersController.createUser({
          email: 'simon.deflesschouwer@mmibordeaux.com',
          firstName: 'test',
          lastName: 'test',
        });
      } catch (e) {
        error = e.response.errors;
      }

      expect(error.length).toBe(1);
      expect(error[0].field).toBe('password');
      expect(error[0].errors).toStrictEqual([
        'password is too short',
        'password should not be empty',
        'password must be a string',
      ]);
    });
  });

  describe('signIn()', () => {
    it('throw an error if the grantType is missing', async () => {
      let error;
      try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore:
        await usersController.signIn({
          email: 'a@a.fr',
        });
      } catch (e) {
        error = e.response.errors;
      }

      expect(error.length).toBe(1);
      expect(error[0].field).toBe('grantType');
      expect(error[0].errors).toStrictEqual([
        'grantType should not be empty',
        'grantType must be a string',
      ]);
    });
    it('throw an error if the grantType is incorrect', async () => {
      let error;
      try {
        await usersController.signIn({
          grantType: 'invalid grant type',
          email: 'a@a.fr',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('Incorrect grantType', HttpStatus.BAD_REQUEST),
      );
    });

    describe('authWithPassword', () => {
      it('should sign in user', async () => {
        const password = 'password';
        const cryptedPassword = await bcrypt.hash(password, 10);
        mockedUserModel.findOne.mockReturnValueOnce({
          password: cryptedPassword,
          _id: 'userId',
        });
        const request = await usersController.signIn({
          grantType: 'password',
          password,
          email: 'user@test.fr',
        });
        expect(request.user.id).toBe('userId');
        expect(isJWT(request.accessToken)).toBeTruthy();
        const tokenContent = jwt.verify(
          request.accessToken,
          process.env.PRIVATE_KEY,
        );
        expect(tokenContent.id).toBe('userId');
      });
      it('should throw an error if the user is not found', async () => {
        let error;
        mockedUserModel.findOne.mockReturnValueOnce(null);
        try {
          await usersController.signIn({
            grantType: 'password',
            email: 'user@test.fr',
            password: 'password',
          });
        } catch (e) {
          error = e;
        }

        expect(error).toStrictEqual(
          new HttpException('User not found', HttpStatus.NOT_FOUND),
        );
      });
      it('should throw an error if the credentials are incorrect', async () => {
        let error;
        const cryptedPassword = await bcrypt.hash('real password', 10);
        mockedUserModel.findOne.mockReturnValueOnce({
          password: cryptedPassword,
          _id: 'userId',
        });
        try {
          await usersController.signIn({
            grantType: 'password',
            email: 'user@test.fr',
            password: 'wrong password',
          });
        } catch (e) {
          error = e;
        }

        expect(error).toStrictEqual(
          new HttpException('Invalid credentials', HttpStatus.FORBIDDEN),
        );
      });
    });

    describe('authWithRefreshToken', () => {
      it('should sign in user', async () => {
        const refreshToken = 'refreshToken';
        mockedUserModel.findById.mockReturnValueOnce({
          save,
          refreshToken,
          _id: 'userId',
          usedRefresh: [],
        });
        const request = await usersController.signIn({
          grantType: 'refreshToken',
          refreshToken,
        });
        expect(save).toHaveBeenCalledTimes(1);
        expect(request.user.id).toBe('userId');
        expect(isJWT(request.accessToken)).toBeTruthy();
        const tokenContent = jwt.verify(
          request.accessToken,
          process.env.PRIVATE_KEY,
        );
        expect(tokenContent.id).toBe('userId');
        expect(request.refreshToken).not.toBe('refreshToken');
      });
      it('should throw an error if the user is not found', async () => {
        let error;
        mockedUserModel.findById.mockReturnValueOnce(null);
        try {
          await usersController.signIn({
            grantType: 'refreshToken',
            refreshToken: 'refreshToken',
          });
        } catch (e) {
          error = e;
        }

        expect(error).toStrictEqual(
          new HttpException('User not found', HttpStatus.NOT_FOUND),
        );
      });
      it('should throw an error if the credentials are incorrect', async () => {
        let error;
        mockedUserModel.findById.mockReturnValueOnce({
          refreshToken: 'stored refresh token',
          _id: 'userId',
        });
        try {
          await usersController.signIn({
            grantType: 'refreshToken',
            refreshToken: 'wrong refresh token',
          });
        } catch (e) {
          error = e;
        }

        expect(error).toStrictEqual(
          new HttpException('Invalid credentials', HttpStatus.FORBIDDEN),
        );
      });
    });
  });

  describe('verifyUser(:id)', () => {
    it('should set user status as verified', async () => {
      mockedUserModel.findById.mockReturnValueOnce(mockedUser);
      const request = await usersController.verifyUser(mockedUser._id);

      expect(mockedUserModel.findById).toBeCalledWith(mockedUser._id);
      expect(save).toBeCalledTimes(1);
      expect(request.message).toBe('User validated');
    });
    it('should throw an error if the user is not found', async () => {
      let error;
      mockedUserModel.findById.mockReturnValueOnce(null);
      try {
        await usersController.verifyUser(mockedUser._id);
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('User not found', HttpStatus.NOT_FOUND),
      );
    });
  });

  describe('requestPasswordReset()', () => {
    it('should send a password change request email', async () => {
      mockedUserModel.findOne.mockResolvedValueOnce({
        save,
        email: 'test@test.fr',
      });
      const request = await usersController.requestPasswordReset({
        email: 'test@test.fr',
      });
      //add expect for sgMail
      expect(request.message).toBe('Password reset requested');
    });
    it('should throw an error if the user is not found', async () => {
      let error;
      mockedUserModel.findOne.mockReturnValueOnce(null);
      try {
        await usersController.requestPasswordReset({
          email: 'test@test.fr',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('User not found', HttpStatus.NOT_FOUND),
      );
    });
  });

  describe('updateUserPassword()', () => {
    it('should update the user password', async () => {
      jest.spyOn(bcrypt, 'hash');
      mockedUserModel.findById.mockReturnValueOnce({
        save,
        _id: 'userId',
      });
      const { message } = await usersController.updateUserPassword(
        mockedUser._id,
        {
          password: 'password',
          passwordRepeat: 'password',
        },
      );

      expect(message).toBe('Password updated');
      expect(bcrypt.hash).toBeCalledWith('password', 10);
      expect(save).toHaveBeenCalled();
      bcrypt.hash.mockRestore();
    });

    it('should throw an error if a field is missing', async () => {
      let error;

      try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore:
        await usersController.updateUserPassword(mockedUser._id, {
          password: 'password',
        });
      } catch (e) {
        error = e.response.errors;
      }

      expect(error.length).toBe(1);
      expect(error[0].field).toBe('passwordRepeat');
      expect(error[0].errors).toStrictEqual([
        'passwordRepeat is too short',
        'passwordRepeat should not be empty',
        'passwordRepeat must be a string',
      ]);
    });

    it('should throw an error if the two passwords mismatch', async () => {
      let error;

      try {
        await usersController.updateUserPassword(mockedUser._id, {
          password: 'password',
          passwordRepeat: 'wrong password',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('Passwords mismatch', HttpStatus.BAD_REQUEST),
      );
    });
  });

  describe('update(:id)', () => {
    it('should update a User without a new password', async () => {
      const user = {
        lastName: 'lastName',
        firstName: 'firstName',
      };

      mockedUserModel.findById.mockReturnValue({
        save,
        firstName: 'oldFirstName',
        lastName: 'oldLastName',
      });
      save.mockResolvedValueOnce(user);
      expect(
        await usersController.updateUser(mockedUser._id, user),
      ).toStrictEqual(user);
      expect(mockedUserModel.findById).toHaveBeenCalledWith(mockedUser._id);
    });

    it('should update a User with a new password', async () => {
      const password = await bcrypt.hash('password', 10);
      bcrypt.hash = jest.fn();

      mockedUserModel.findById.mockReturnValueOnce({
        ...mockedUser,
        password,
      });

      save.mockResolvedValueOnce({ ...mockedUser, password: 'newPassword' });

      const request = await usersController.updateUser(mockedUser._id, {
        oldPassword: 'password',
        newPassword: 'newPassword',
        newPasswordRepeat: 'newPassword',
      });

      expect(request).toStrictEqual({ ...mockedUser, password: 'newPassword' });
      expect(bcrypt.hash).toHaveBeenCalledWith('newPassword', 10);
      expect(mockedUserModel.findById).toHaveBeenCalledWith(mockedUser._id);
    });

    it('should throw an error if the id is invalid', async () => {
      let error;

      try {
        await usersController.updateUser('invalidId', {
          firstName: 'firstName',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('Invalid ID', HttpStatus.BAD_REQUEST),
      );
      expect(mockedUserModel.findById).toHaveBeenCalledTimes(0);
    });

    it('should throw an error if the user is not found', async () => {
      let error;

      mockedUserModel.findById.mockReturnValueOnce(null);

      try {
        await usersController.updateUser(mockedUser._id, {
          firstName: 'firstName',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException('User not found', HttpStatus.NOT_FOUND),
      );
      expect(mockedUserModel.findById).toHaveBeenCalledTimes(1);
    });

    it('should throw an error if the password mismatch', async () => {
      let error;

      mockedUserModel.findById.mockReturnValueOnce({
        ...mockedUser,
        password: 'oldPassword',
      });

      try {
        await usersController.updateUser(mockedUser._id, {
          firstName: 'firstName',
          newPassword: 'newPassword',
          newPasswordRepeat: 'wrongPassword',
          oldPassword: 'oldPassword',
        });
      } catch (e) {
        error = e;
      }

      expect(error).toStrictEqual(
        new HttpException(
          'New password and confirmation do not match',
          HttpStatus.BAD_REQUEST,
        ),
      );
      expect(mockedUserModel.findById).toHaveBeenCalledTimes(1);
    });
  });
});
