# expressjs_auth

expressjs_auth is a simple, flexible, and fast solution for creating Express.js applications with built-in authentication. It supports both MySQL and MongoDB, providing all the necessary middlewares, services, controllers, and routes to get started quickly.

## Features
- **Database Support**: Easily connect your project to either MySQL or MongoDB.  
- **JWT Authentication**: Secure authentication using JSON Web Tokens (JWT).  
- **User Registration and Login**: Prebuilt endpoints for user sign-up and login with password encryption.  
- **Email Verification**: Users receive a verification email upon registration to activate their account.  
- **Account Verification Flow**: Login is only allowed after the user has verified their email.  
- **Quick Setup**: Create and configure a fully functional authentication system with minimal effort.


## Installation

To create a expressjs_auth project, run:

```bash
npx expressjs_auth create name-project 
```
This command will generate a fully configured project directory.
## Usage
1. Navigate to the project directory:
```bash
cd name-project
```
2. Install dependencies:
```bash
npm install
```
3. Configure email credentials in the .env file:

- *EMAIL_USER=ton.email@gmail.com*
- *EMAIL_PASS=ton_mot_de_passe_app*

4. Run the server:
```bash
npm start
```
## Test Login and Registration

- **POST** `http://localhost:3000/api/register`  
  **Request body:**  
  ```json
  {
    "email": "ton.email@gmail.com",
    "password": "Amineu&12&"
  }

- *Upon registration, a verification email is sent to the user.*

- *The user must click the link in the email to verify their account before being able to login.*
#### Verify Account

   - *Click the verification link received by email to activate your account.*

#### Login


- **POST** `http://localhost:3000/api/login`  
  **Request body:**  
  ```json
  {
    "email": "ton.email@gmail.com",
    "password": "Amineu&12&"
  }

- *Login is only successful if the account is verified.*
Your project will be live and ready for customization!
## Email Demo and Screenshots

- [Email sent](https://github.com/mouhamedkl/expressjs_auth/blob/main/images/emailsend.png)  
- [Validation](https://github.com/mouhamedkl/expressjs_auth/blob/main/images/validation.png)  
- [Register](https://github.com/mouhamedkl/expressjs_auth/blob/main/images/register.png)  
- [Login](https://github.com/mouhamedkl/expressjs_auth/blob/main/images/logintoken.png)  
- [Verify Email](https://github.com/mouhamedkl/expressjs_auth/blob/main/images/verifyemail.png)  
- [Open Link](https://github.com/mouhamedkl/expressjs_auth/blob/main/images/openlink.png)  

## Licence

[MIT](https://github.com/mouhamedkl/expressjs_auth/blob/main/Licence)


