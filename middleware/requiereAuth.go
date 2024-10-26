package middleware

import (
	"fmt"
	"go-jwt/initializers"
	"go-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
	// Obtener el token de la cookie
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No se encontró el token de autorización"})
		return
	}

	// Decodificar y validar el token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
		return
	}

	// Validar las reclamaciones del token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token no válido"})
		return
	}

	// Verificar la expiración del token
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expirado"})
		return
	}

	// Buscar al usuario en la base de datos
	var user models.User
	if err := initializers.DB.First(&user, claims["sub"]).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Usuario no encontrado"})
		return
	}

	// Adjuntar el usuario a la solicitud
	c.Set("user", user)

	// Continuar con la solicitud
	c.Next()
}
