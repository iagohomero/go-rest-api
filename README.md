<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
[![Go Version][go-shield]][go-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/iagohomero/go-rest-api">
    <img src="https://go.dev/images/gophers/ladder.svg" alt="Logo" width="120" height="120">
  </a>

  <h3 align="center">go-rest-api</h3>

  <p align="center">
    A production-ready boilerplate to accelerate the development of RESTful APIs in Go
    <br />
    <a href="#usage"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="#">View Demo</a>
    ·
    <a href="https://github.com/iagohomero/go-rest-api/issues">Report Bug</a>
    ·
    <a href="https://github.com/iagohomero/go-rest-api/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
        <li><a href="#key-features">Key Features</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#project-structure">Project Structure</a></li>
    <li><a href="#api-documentation">API Documentation</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

**go-rest-api** is a production-ready boilerplate designed to accelerate the creation of RESTful APIs in Go. It provides a solid, ready-to-use foundation with common functionalities like user management and authentication already implemented, allowing developers to focus on core business logic instead of rewriting repetitive code for registration, login, and security.

### Why Use This Boilerplate?

* **Save Time**: Stop rewriting authentication and user management code for every new project
* **Best Practices**: Built following Go best practices and clean architecture principles
* **Production Ready**: Includes essential features like logging, error handling, and graceful shutdown
* **Scalable Structure**: Organized codebase that grows with your project
* **Well Tested**: Comprehensive test coverage to ensure reliability

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

This project leverages modern Go libraries and tools to provide a robust foundation:

* [![Go][Go-badge]][Go-url] - **Go 1.24** - Primary programming language
* [![Fiber][Fiber-badge]][Fiber-url] - **Fiber v2** - Fast Express-inspired web framework
* [![PostgreSQL][PostgreSQL-badge]][PostgreSQL-url] - **PostgreSQL** - Reliable relational database
* [![GORM][GORM-badge]][GORM-url] - **GORM** - The fantastic ORM library for Go
* [![JWT][JWT-badge]][JWT-url] - **JWT** - JSON Web Tokens for authentication
* [![OAuth2][OAuth2-badge]][OAuth2-url] - **OAuth 2.0** - Google social login integration
* [![Swagger][Swagger-badge]][Swagger-url] - **Swagger** - API documentation
* [![Docker][Docker-badge]][Docker-url] - **Docker** - Containerization support

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Key Features

- ✅ **Complete User Management API** - Full CRUD operations (Create, Read, Update, Delete)
- ✅ **Secure JWT Authentication** - Token-based authentication with access and refresh tokens
- ✅ **OAuth 2.0 Integration** - "Login with Google" functionality
- ✅ **Password Recovery Flow** - Secure password reset with email verification
- ✅ **Email Service** - Transactional email support with SMTP configuration
- ✅ **API Documentation** - Auto-generated Swagger/OpenAPI documentation
- ✅ **Automated Database Migrations** - Migrations run automatically on application startup
- ✅ **Clean Architecture** - Well-organized, maintainable codebase structure
- ✅ **Middleware Support** - Authentication, logging, rate limiting, and recovery middleware
- ✅ **Docker Support** - Full Docker and Docker Compose configuration
- ✅ **Comprehensive Testing** - Unit and integration tests with coverage reports
- ✅ **Code Quality Assurance** - Configured with golangci-lint for maintaining code standards
- ✅ **Environment Configuration** - Flexible configuration using Viper
- ✅ **Graceful Shutdown** - Proper cleanup and connection management
- ✅ **Role-Based Access Control** - RBAC implementation for permissions management

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

Before you begin, ensure you have the following installed:

* **Go 1.24 or higher**
  ```sh
  go version
  ```

* **Docker and Docker Compose** (optional, for containerized development)
  ```sh
  docker --version
  docker-compose --version
  ```

* **PostgreSQL** (if not using Docker)
  ```sh
  psql --version
  ```

* **golang-migrate** (for database migrations)
  ```sh
  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
  ```

### Installation

#### Option 1: Local Development (Recommended for Development)

1. **Clone the repository**
   ```sh
   git clone https://github.com/iagohomero/go-rest-api.git
   cd go-rest-api
   ```

2. **Install development tools** (optional, but recommended)
   ```sh
   make install-tools
   ```
   This will install: Air (hot reload), golangci-lint, Swagger CLI, and golang-migrate

3. **Install dependencies**
   ```sh
   make deps
   ```

4. **Configure environment variables**
   
   Copy the example environment file and update it with your settings:
   ```sh
   cp .env.example .env
   ```
   
   Then edit the `.env` file with your configuration:
   ```env
   # Server Configuration
   APP_ENV=dev
   APP_HOST=0.0.0.0
   APP_PORT=8080
   APP_URL=http://localhost:8080

   # Database Configuration
   DB_HOST=localhost        # Use 'postgres' if running with Docker
   DB_USER=postgres
   DB_PASSWORD=your_secure_password
   DB_NAME=godb
   DB_PORT=5432

   # JWT Configuration
   JWT_SECRET=your_jwt_secret_key_here
   JWT_ACCESS_EXP_MINUTES=30
   JWT_REFRESH_EXP_DAYS=30

   # SMTP Configuration (for emails)
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your_email@gmail.com
   SMTP_PASSWORD=your_email_password
   EMAIL_FROM=noreply@yourapp.com

   # OAuth2 Configuration (Google)
   GOOGLE_CLIENT_ID=your_google_client_id.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   REDIRECT_URL=http://localhost:8080/v1/auth/google-callback
   ```

5. **Build and run the application** (migrations run automatically)
   ```sh
   make run
   ```
   
   Or for development with hot reload:
   ```sh
   make dev
   ```

6. **Verify the installation**
   ```sh
   curl http://localhost:8080/v1/health
   ```

#### Option 2: Docker (Recommended for Quick Start)

1. **Clone the repository**
   ```sh
   git clone https://github.com/iagohomero/go-rest-api.git
   cd go-rest-api
   ```

2. **Configure environment variables**
   ```sh
   cp .env.example .env
   ```
   
   Edit the `.env` file and ensure `DB_HOST=postgres` (not localhost)

3. **Start all services with Docker Compose**
   ```sh
   make docker-up
   ```
   
   This will start:
   - PostgreSQL database
   - Adminer (database management UI at http://localhost:8081)
   - The Go API application

4. **Database migrations run automatically** - No manual migration step needed! The application will automatically run all pending migrations when it starts.

5. **Verify the installation**
   ```sh
   curl http://localhost:8080/v1/health
   ```

6. **View logs** (optional)
   ```sh
   make docker-logs
   ```

7. **Stop services** (when done)
   ```sh
   make docker-down
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE -->
## Usage

### API Documentation

The complete API documentation is available through Swagger UI. After starting the application, visit:

```
http://localhost:8080/swagger/index.html
```

### Available Endpoints

#### Authentication
- `POST /v1/auth/register` - Register a new user
- `POST /v1/auth/login` - Login with email and password
- `POST /v1/auth/refresh` - Refresh access token
- `POST /v1/auth/forgot-password` - Request password reset
- `POST /v1/auth/reset-password` - Reset password with token
- `GET /v1/auth/google-login` - Login with Google (OAuth 2.0)
- `GET /v1/auth/google-callback` - Google OAuth callback

#### User Management
- `GET /v1/users` - Get all users (requires authentication)
- `GET /v1/users/:id` - Get user by ID
- `PUT /v1/users/:id` - Update user
- `DELETE /v1/users/:id` - Delete user

#### Health Check
- `GET /v1/health` - Check API status

### Development Commands

The project includes a comprehensive Makefile with useful commands:

```sh
# Development
make dev              # Run with hot reload (requires air)
make build            # Build the application
make run              # Build and run the application

# Testing
make test             # Run tests
make test-coverage    # Run tests with coverage report
make lint             # Run linter

# Docker
make docker-build     # Build Docker image
make docker-up        # Start all services with Docker Compose
make docker-down      # Stop all services
make docker-logs      # View Docker logs

# Database Migrations
make migrate-create name=migration_name   # Create new migration
make migrate-up                           # Run all pending migrations (development only)
make migrate-down                         # Rollback last migration (development only)
make docker-migrate-up                    # Run all pending migrations using Docker (development only)
make docker-migrate-down                  # Rollback last migration using Docker (development only)

# Note: In production, migrations run automatically when the application starts

# Documentation
make swag             # Generate/update Swagger documentation

# Utilities
make clean            # Clean build artifacts
make deps             # Download and tidy dependencies
make install-tools    # Install development tools
```

### Example API Calls

**Register a new user:**
```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

**Access protected endpoint:**
```bash
curl -X GET http://localhost:8080/v1/users \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- PROJECT STRUCTURE -->
## Project Structure

```
go-rest-api/
├── cmd/
│   └── api/
│       └── main.go              # Application entry point
├── internal/
│   ├── auth/                    # Authentication logic
│   ├── user/                    # User management
│   ├── common/                  # Shared utilities
│   │   ├── crypto/             # Password hashing
│   │   ├── errors/             # Error handling
│   │   ├── jwt/                # JWT utilities
│   │   ├── logger/             # Logging
│   │   └── validation/         # Request validation
│   ├── config/                 # Configuration management
│   ├── database/               # Database connection
│   ├── email/                  # Email service
│   ├── healthcheck/            # Health check endpoint
│   ├── middleware/             # HTTP middleware
│   ├── rbac/                   # Role-based access control
│   ├── routes/                 # Route definitions
│   └── server/                 # Server setup
├── migrations/                  # Database migrations
├── api/
│   └── swagger/                # API documentation
├── docker-compose.yml          # Docker Compose configuration
├── Dockerfile                  # Docker image definition
├── Makefile                    # Build automation
├── go.mod                      # Go module definition
└── .env.example               # Environment variables template
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feat/amazing-feature`)
3. Commit your Changes (`git commit -m 'feat: add some amazing-feature'`)
4. Push to the Branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

Iago Homero - iagohomero@gmail.com

Project Link: [https://github.com/iagohomero/go-rest-api](https://github.com/iagohomero/go-rest-api)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[go-shield]: https://img.shields.io/badge/Go-1.24-00ADD8?style=for-the-badge&logo=go&logoColor=white
[go-url]: https://go.dev/
[license-shield]: https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge
[license-url]: https://github.com/iagohomero/go-rest-api/blob/main/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/your_username

[Go-badge]: https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white
[Go-url]: https://go.dev/
[Fiber-badge]: https://img.shields.io/badge/Fiber-00ACD7?style=for-the-badge&logo=fiber&logoColor=white
[Fiber-url]: https://gofiber.io/
[PostgreSQL-badge]: https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white
[PostgreSQL-url]: https://www.postgresql.org/
[GORM-badge]: https://img.shields.io/badge/GORM-00ADD8?style=for-the-badge&logo=go&logoColor=white
[GORM-url]: https://gorm.io/
[JWT-badge]: https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white
[JWT-url]: https://jwt.io/
[OAuth2-badge]: https://img.shields.io/badge/OAuth2.0-EB5424?style=for-the-badge&logo=auth0&logoColor=white
[OAuth2-url]: https://oauth.net/2/
[Swagger-badge]: https://img.shields.io/badge/Swagger-85EA2D?style=for-the-badge&logo=swagger&logoColor=black
[Swagger-url]: https://swagger.io/
[Docker-badge]: https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white
[Docker-url]: https://www.docker.com/

