package autentication

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"jwt-golang/models"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go/request"

	jwt "github.com/dgrijalva/jwt-go"
)

// criar chave rsa privada
// $ openssl genrsa -outprivate.rsa 1024

// criar chave pública
// $ openssl rsa -in private.rsa -pubout > public.rsa.pub

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("./private.rsa")
	if err != nil {
		log.Fatal("não foi possivel ccarrrega a chave privada")
	}

	publicBytes, err := ioutil.ReadFile("./public.rsa.pub")
	if err != nil {
		log.Fatal("Não foi possivel carregar a chave publica")

	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("Erro ao converter chave privada")
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("Não foi possivel fazer o parse da publicKey")
	}

}

// gera token
func GenerateJWT(user models.User) string {

	claims := models.Claim{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour + 1).Unix(),
			Issuer:    "Teste jwt",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("não se pode montar o token")
	}

	return result
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		panic(err)
		fmt.Println("Erro ao decodificar")
	}

	if user.Name == "claudiano" && user.Password == "claudiano" {
		fmt.Println("usuario logado")
		user.Password = ""
		user.Role = "admin"

		token := GenerateJWT(user)
		result := models.ResponseToken{token}
		jsonResult, err := json.Marshal(result)
		if err != nil {
			panic(err)
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResult)

	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Println("usuario invalido")
	}
}

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &models.Claim{},
		func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				fmt.Println("token expirado")
				return
			case jwt.ValidationErrorSignatureInvalid:
				fmt.Println("Dados invalido, token informado não coincide")
				return
			default:
				fmt.Println("Token invalido")
				return

			}
		default:
			fmt.Println("Token informado invalido")
			return

		}
	}

	if token.Valid {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, "bem vindo ao sistema")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Token não autorizado")
	}
}
