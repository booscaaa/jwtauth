package jwtauth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/crypto/bcrypt"
)

type Session struct {
	Hash      string
	IsRevoked bool
	Access    Access
	Auth      Auth
	DB        *sql.DB
}

func b2s(b []byte) string {
	/* #nosec G103 */
	return *(*string)(unsafe.Pointer(&b))
}

func structScan(rows *sql.Rows, model interface{}) error {
	v := reflect.ValueOf(model)
	if v.Kind() != reflect.Ptr {
		return errors.New("must pass a pointer, not a value, to StructScan destination") // @todo add new error message
	}

	v = reflect.Indirect(v)
	t := v.Type()

	cols, _ := rows.Columns()

	var m map[string]interface{}
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return err
		}

		m = make(map[string]interface{})
		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			m[colName] = *val
		}

	}

	for i := 0; i < v.NumField(); i++ {
		field := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]

		if item, ok := m[field]; ok {
			if v.Field(i).CanSet() {
				if item != nil {
					switch v.Field(i).Kind() {
					case reflect.String:
						v.Field(i).SetString(b2s(item.([]uint8)))
					case reflect.Float32, reflect.Float64:
						v.Field(i).SetFloat(item.(float64))
					case reflect.Int, reflect.Int32, reflect.Int64:
						v.Field(i).SetInt(item.(int64))
					case reflect.Ptr:
						if reflect.ValueOf(item).Kind() == reflect.Bool {
							itemBool := item.(bool)
							v.Field(i).Set(reflect.ValueOf(&itemBool))
						}
					case reflect.Struct:
						v.Field(i).Set(reflect.ValueOf(item))
					default:
						fmt.Println(t.Field(i).Name, ": ", v.Field(i).Kind(), " - > - ", reflect.ValueOf(item).Kind()) // @todo remove after test out the Get methods
					}
				}
			}
		}
	}

	return nil
}

//SessionCreate .
func SessionCreate(access Access, writer http.ResponseWriter) {
	session := Session{
		Hash:   "",
		Access: Access{},
		Auth:   Auth{},
		DB:     GetConnection(),
	}

	defer session.DB.Close()

	// verifica se existe acesso para os dados digitados
	{
		rows, err := session.DB.Query(
			`	SELECT * from access 
				where login = $1 and 
				password = crypt($2, password) 
				LIMIT 1;	`,
			access.Login,
			access.Password,
		)
		e, isEr := CheckErr(err)

		if isEr {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write(e.ReturnError())
			return
		}

		err = structScan(rows, &session.Access)

		e, isEr = CheckErr(err)

		if isEr {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write(e.ReturnError())
			return
		}

	}

	// caso não tenha retorna acesso negado
	if session.Access.ID == 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write(ReturnMessage("Acesso negado!"))
		return
	}

	// caso tenha cria o token
	tokenAuth := TokenAuth{
		Access: session.Access,
		Exp:    time.Now().Add(time.Second * 40).Unix(),
	}

	// verifica se já tem token de recuperação gravado no banco
	{
		session.DB.QueryRow(
			`	SELECT refresh, is_revoked from auth 
				where access_id = $1 
				LIMIT 1;	`,
			session.Access.ID,
		).Scan(
			&session.Hash,
			&session.IsRevoked,
		)

		//se tem e está revogado retorna acesso negado
		if session.IsRevoked {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write(ReturnMessage("Acesso negado!"))
			return
		}
	}

	//se não tiver token de recuperação ou se tiver se revogação atualiza o token de acesso
	{
		tx, err := session.DB.Begin()
		e, isEr := CheckErr(err)

		if isEr {
			tx.Rollback()
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write(e.ReturnError())
			return
		}

		{
			// se tiver token de recuperação atualiza o memso
			if session.Hash != "" {
				session.Auth = CreateToken(tokenAuth, session.Hash)
				stmt, err := tx.Prepare(`UPDATE auth set token = $1 where access_id = $2;`)

				e, isEr := CheckErr(err)

				if isEr {
					tx.Rollback()
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write(e.ReturnError())
					return
				}

				fmt.Println(session.Access.ID)

				_, err = stmt.Exec(
					session.Auth.Token,
					session.Access.ID,
				)
				e, isEr = CheckErr(err)

				if isEr {
					tx.Rollback()
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write(e.ReturnError())
					return
				}
			} else { // se não tiver cria um novo
				password := []byte(os.Getenv("BCRYPT_HASH_SECRET"))
				hashedPassword, _ := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)

				session.Auth = CreateToken(tokenAuth, string(hashedPassword))
				stmt, err := tx.Prepare(`INSERT INTO auth (token, refresh, type, access_id) VALUES ($1, $2, $3, $4);`)

				e, isEr := CheckErr(err)

				if isEr {
					tx.Rollback()
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write(e.ReturnError())
					return
				}

				fmt.Println(session.Access.ID)

				_, err = stmt.Exec(
					session.Auth.Token,
					session.Auth.Refresh,
					session.Auth.Type,
					session.Access.ID,
				)
				e, isEr = CheckErr(err)

				if isEr {
					tx.Rollback()
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write(e.ReturnError())
					return
				}
			}

		}

		tx.Commit()
	}

	payload, err := json.Marshal(session.Auth)
	e, isEr := CheckErr(err)

	if isEr {
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write(e.ReturnError())
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Write(payload)

	return
}

//SessionRefresh .
func SessionRefresh(bearToken string, writer http.ResponseWriter) {
	strArr := strings.Split(bearToken, " ")
	// é necessario 4 parametros no header de authorization
	if len(strArr) == 4 {
		session := Session{
			Hash:   strArr[2],
			Access: Access{},
			Auth: Auth{
				Token:   strArr[1],
				Refresh: strArr[2],
				Type:    strArr[3],
			},
			DB: GetConnection(),
		}

		defer session.DB.Close()

		// busca o id do acesso e testa se os dados estão corretos
		{
			session.DB.QueryRow(
				`	SELECT access_id from auth 
					where refresh = $1 and 
					token = $2 and 
					type = $3 and 
					is_revoked is false 
					LIMIT 1;	`,
				session.Hash,
				session.Auth.Token,
				session.Auth.Type,
			).Scan(
				&session.Access.ID,
			)

			// caso não retorna acesso negado
			if session.Access.ID == 0 {
				writer.WriteHeader(http.StatusUnauthorized)
				writer.Write(ReturnMessage("Acesso negado!"))
				return
			}
		}

		// se estiver tudo ok busca todos os dados do acesso
		{
			session.DB.QueryRow(
				`SELECT id, login, password, email from access where id = $1 LIMIT 1;`,
				session.Access.ID,
			).Scan(
				&session.Access.ID,
				&session.Access.Login,
				&session.Access.Password,
				&session.Access.Email,
			)
		}

		// cria um novo token com nova data e expiração

		// caso tenha cria o token
		tokenAuth := TokenAuth{
			Access: session.Access,
			Exp:    time.Now().Add(time.Second * 40).Unix(),
		}

		session.Auth = CreateToken(tokenAuth, session.Hash)

		// atualiza o token existente na base
		{
			tx, err := session.DB.Begin()
			e, isEr := CheckErr(err)

			if isEr {
				tx.Rollback()
				writer.WriteHeader(http.StatusInternalServerError)
				writer.Write(e.ReturnError())
				return
			}

			session.Auth = CreateToken(tokenAuth, session.Hash)
			stmt, err := tx.Prepare(`UPDATE auth set token = $1 where access_id = $2;`)

			e, isEr = CheckErr(err)

			if isEr {
				tx.Rollback()
				writer.WriteHeader(http.StatusInternalServerError)
				writer.Write(e.ReturnError())
				return
			}

			_, err = stmt.Exec(
				session.Auth.Token,
				session.Access.ID,
			)
			e, isEr = CheckErr(err)

			if isEr {
				tx.Rollback()
				writer.WriteHeader(http.StatusInternalServerError)
				writer.Write(e.ReturnError())
				return
			}

			tx.Commit()
		}

		payload, err := json.Marshal(session.Auth)
		e, isEr := CheckErr(err)

		if isEr {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write(e.ReturnError())
			return
		}

		writer.WriteHeader(http.StatusOK)
		writer.Write(payload)
		return
	}

	writer.WriteHeader(http.StatusUnauthorized)
	writer.Write(ReturnMessage("Acesso negado!"))
	return
}
