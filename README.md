
# JWT-Based User Registration and Authentication System


JWT-Based User Registration and Authentication System Backend is a RESTful API developed using Spring Boot. This backend service handles user authentication and role-based access control for a drug inventory management system.

## Features

1). User Authentication: Allows users to register and authenticate.

2). Role-Based Access Control: Manages different roles (USER, DOCTOR, ADMIN) with specific permissions.

3). JWT Authentication: Secures endpoints using JSON Web Tokens (JWT).


## Technologies

1). Java 21 (or the version you used)

2). Spring Boot 3.x

3). Spring Security

4). JWT (JSON Web Tokens)

5). PostgreSQL (or your database)

6). Maven/Gradle (specify which one you use)

# How It Works

## 1. User Registration

* Endpoint: POST /api/v1/auth/register
* Description: This endpoint allows new users to register by providing their personal details and role. Upon successful registration, the user receives a JWT token for authentication.
* Request Body:
```bash
{
  "firstname": "Srisankaran",
  "lastname": "V",
  "email": "srisankaran@example.com",
  "password": "password123",
  "role": "USER"
}
```
* Response Body:
```bash
{
  "token": "jwt_token"
}

```

## 2. User Authentication

* Endpoint: POST /api/v1/auth/authenticate
* Description: This endpoint allows users to log in by providing their email and password. If the credentials are valid, the server responds with a JWT token.
* Request Body:
```bash
{
  "email": "srisankaran@example.com",
  "password": "password123"
}

```
* Response Body:
```bash
{
  "token": "jwt_token"
}

```
## 3. Role-Based Access Control

* USER: Basic access.
* DOCTOR: Access to specific endpoints related to medical operations.
* ADMIN: Full access to all endpoints, including administrative functionalities.


## 4. JWT Authentication

* JWT Tokens: Upon successful registration or authentication, users receive a JWT token. This token must be included in the Authorization header as a Bearer token for accessing protected endpoints.
## 5. Security Configuration

* CSRF Protection: Disabled for simplicity in this demo. In production, it should be enabled and configured properly.
* Session Management: Stateless, meaning that the server does not store any session information.


# Testing

* Unit Tests: Located in src/test/java. Run with ./mvnw test or ./gradlew test.


# Contributing
* Fork the repository.
* Create a new branch (git checkout -b feature/your-feature).
* Commit your changes (git commit -am 'Add new feature').
* Push to the branch (git push origin feature/your-feature).
* Create a new Pull Request.

# Acknowledgements
* Spring Boot
* PostgreSQL
* JWT
