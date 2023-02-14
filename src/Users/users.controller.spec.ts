// import { getModelToken } from '@nestjs/mongoose';
// import { Test, TestingModule } from '@nestjs/testing';
// import { User } from '../core/schemas/Users.schema';

// import { UsersController } from './users.controller';
// import { UsersService } from './users.service';

// describe('UsersController', () => {
//   let UsersController: UsersController;
//   //let UsersService: UsersService;

//   const mockedUserModel = {
//     find: jest.fn(),
//     findById: jest.fn(),
//     findByIdAndDelete: jest.fn(),
//   };

//   const mockData = [{ title: 'test', comment: 'testComment', save: jest.fn() }];

//   beforeEach(async () => {
//     const module: TestingModule = await Test.createTestingModule({
//       controllers: [UsersController],
//       providers: [
//         UsersService,
//         { provide: getModelToken(User.name), useValue: mockedUserModel },
//       ],
//     }).compile();

//     //UsersService = module.get<UsersService>(UsersService);
//     UsersController = module.get<UsersController>(UsersController);
//   });

//   describe('get()', () => {
//     it('should return all the Users', async () => {
//       mockedUserModel.find.mockReturnValue(mockData);
//       expect(await UsersController.getUsers()).toStrictEqual(mockData);
//     });
//   });

//   describe('get(:id)', () => {
//     it('should return a specific User', async () => {
//       mockedUserModel.findById.mockReturnValue(mockData[0]);
//       expect(await UsersController.getUser('test')).toStrictEqual(
//         mockData[0],
//       );
//       expect(mockedUserModel.findById).toHaveBeenCalledWith('test');
//     });
//   });

//   describe('delete(:id)', () => {
//     it('should delete a User', async () => {
//       expect(await UsersController.deleteUser('test')).toStrictEqual({
//         success: true,
//       });
//       expect(mockedUserModel.findByIdAndDelete).toHaveBeenCalledWith('test');
//     });
//   });

//   describe('update(:id)', () => {
//     it('should delete a User', async () => {
//       mockedUserModel.findById.mockReturnValue(mockData[0]);
//       mockData[0].save.mockReturnValue({
//         title: 'test1',
//         comment: 'testComment',
//       });
//       const newUser = new User();
//       newUser.title = 'test1';
//       newUser.comment = 'testComment';
//       expect(
//         await UsersController.updateUser('test', newUser),
//       ).toStrictEqual({
//         title: 'test1',
//         comment: 'testComment',
//       });
//       expect(mockedUserModel.findById).toHaveBeenCalledWith('test');
//     });
//   });
// });
