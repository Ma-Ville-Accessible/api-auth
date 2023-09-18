interface user {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isVerified: boolean;
}

interface auth {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  refreshToken: string;
  user: user;
}

interface create {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  refreshToken: string;
}

interface update {
  firstName: string;
  lastName: string;
}

interface verify {
  message: string;
}

interface requestPassword {
  message: string;
}

interface updatePassword {
  message: string;
}

export { user, auth, create, update, verify, requestPassword, updatePassword };
