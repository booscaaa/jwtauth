# JWT Auth Golang

<!-- <img src="https://raw.githubusercontent.com/booscaaa/midow/master/screenshots/midow.png"  width="100%" /> -->


## About this Project

The idea of the App is:

_"Show an example of how to manage access to an api with golang and jwt"._

<br>

## Why?

This project is part of my personal portfolio, so, I'll be happy if you could provide me any feedback about the project, code, structure or anything that you can report that could make me a better developer!

Email-me: boscardinvinicius@gmail.com

Connect with me at [LinkedIn](https://www.linkedin.com/in/booscaaa/).


<br>

## Functionalities

- Verify auth and generete a token object to manege access.

- Get a refreshed token.


<br>

## Getting Started

### Prerequisites

To run this project in the development mode, you'll need to have a basic environment to run: 
- A Golang SDK, that can be found [here](https://golang.org/dl/).


<br>

### Installing


**Cloning the Repository**

```
$ git clone https://github.com/booscaaa/jwtauth

$ cd jwtauth/example
```
<br>

**Installing dependencies**

```
$ go mod download
```
<br>

### Running
- Configure o arquivo .env com os dados necessarios encontrados no arquivo .env.example

- Rode:

```
$ go run main.go
```

<br>
<br>
<br>

### URLs to show the aplications

- API = http://YOUR_MACHINE_IP:8080

<br>

## Libs to build the application

- [JWT](github.com/dgrijalva/jwt-go) - Library for golang jwt
- [Gorila Handlers](github.com/gorilla/handlers) - Library for config compress files
- [Gorila Mux](github.com/gorilla/mux) - Library for config routes
- [Env](github.com/joho/godotenv) - To get .env file
- [PQ](github.com/lib/pq) - To get access to postgres database
- [Map struct](github.com/mitchellh/mapstructure) - To convert jwt claims to structs
- [Crypto](golang.org/x/crypto) - To get a BCrypt hash to manege the token

<br>
<br>

You can send how many PR's do you want, I'll be glad to analyse and accept them! And if you have any question about the project...

Email-me: boscardinvinicius@gmail.com

Connect with me at [LinkedIn](https://www.linkedin.com/in/booscaaa/)

Thank you!

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/booscaaa/jwtauth/blob/master/LICENSE) file for details