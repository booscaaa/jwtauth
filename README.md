# JWT Auth Golang for Postgres


## About this Project

The idea of the App is:

_"A library to auth with jwt in golang with postgres"._


## Why?

This project is part of my personal portfolio, so, I'll be happy if you could provide me any feedback about the project, code, structure or anything that you can report that could make me a better developer!

Email-me: boscardinvinicius@gmail.com

Connect with me at [LinkedIn](https://www.linkedin.com/in/booscaaa/).



## Functionalities

- Verify auth and generete a token object with 40 seconds expiration  to manage access.

- Get a refreshed token.



## Getting Started

### Prerequisites

To run this project in the development mode, you'll need to have a basic environment to run: 
- A Golang SDK, that can be found [here](https://golang.org/dl/).


### Installing


**Using lib**

Config two tables into your database exactly like this!

<img src="https://raw.githubusercontent.com/booscaaa/jwtauth/master/docs/jwt.png"  width="50%" />

<br>
<br>

```bash
$ go get github.com/booscaaa/jwtauth
```
<br>
<br>
Config the file .env with .env.example

```env
DB_HOST=
DB_USER=
DB_PASSWORD=
DB_NAME=
BCRYPT_HASH_SECRET=    #secret hash for reniew token
HASH_CRYPT=    #secret hash for JWT
```
<br><br>
Import lib

```golang
import (
	"github.com/booscaaa/jwtauth"
)
```
<br>
<br>
Call SessionCreate to create a valid session

```golang
func Create(writer http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
	} else {
		var access jwtauth.Access
		if err := json.NewDecoder(r.Body).Decode(&access); err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte("500 - Something bad happened!"))
		} else {
			defer r.Body.Close()
			SessionCreate(access, writer)
		}
	}
}
```
<br>
<br>

Call SessionRefresh to create new valid session
```golang
func Refresh(writer http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
	} else {
		bearToken := r.Header.Get("Authorization")  // this bear token must be 4 params -- Bearer <token> <refreshCryptToken> <typeToken>
		SessionRefresh(bearToken, writer)
	}
}
```
<br>
<br>
Then create a middleware to manage the auth token in your application

```golang
func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		bearToken := request.Header.Get("Authorization") // bear token must be 2 params -- Bearer <token>
		if isAuth, access := VerifyToken(bearToken); isAuth {
			fmt.Println(access.Login)
			request = SetContextData(request, &access) // passing access struct to the request context to get it into controller method
			next.ServeHTTP(response, request)
		} else {
			response.WriteHeader(http.StatusUnauthorized)
			response.Write(ReturnMessage("Acesso negado"))
		}
	})
}

```
<br>
<br>
To get the access struct into your controller method just do it:

```golang
func YourMethodController(response http.ResponseWriter, request *http.Request) {
	a := GetContextData(request)
}
```
<br>

## Libs to build the application

- [JWT](github.com/dgrijalva/jwt-go) - Library for golang jwt
- [Env](github.com/joho/godotenv) - To get .env file
- [PQ](github.com/lib/pq) - To get access to postgres database
- [Map struct](github.com/mitchellh/mapstructure) - To convert jwt claims to structs
- [Crypto](golang.org/x/crypto) - To get a BCrypt hash to manage the token

<br>

You can send how many PR's do you want, I'll be glad to analyse and accept them! And if you have any question about the project...

Email-me: boscardinvinicius@gmail.com

Connect with me at [LinkedIn](https://www.linkedin.com/in/booscaaa/)

Thank you!

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/booscaaa/jwtauth/blob/master/LICENSE) file for details