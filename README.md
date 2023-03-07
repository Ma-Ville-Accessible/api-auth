## Ma Ville Accessible - Api :rocket:

![example workflow](https://github.com/Ma-Ville-Accessible/api/actions/workflows/ci.yml/badge.svg)

### Getting started

install deps

```bash
$ yarn
```

start the project

```bash
$ yarn dev
```

### Routes

#### /users

- get[:id] => get user informations
- patch[:id] => update a user
- post[] => create a user
- delete[:id] => delete a user

#### /users/authenticate
 - post[] => get an access token with a specified grantType(password, refreshToken)

