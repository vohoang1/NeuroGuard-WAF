package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"neuroguard-api/internal/db"
	"neuroguard-api/internal/models"
)

type AuthHandler struct {
	JWTSecret []byte
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIError{Error: "Invalid request format", Message: err.Error()})
		return
	}

	var user models.User
	if err := db.DB.Preload("Role").Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized", Message: "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized", Message: "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID.String(),
		"tenant_id": user.TenantID.String(),
		"role":      user.Role.Name,
		"exp":       time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(h.JWTSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIError{Error: "Token error", Message: "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, models.LoginResponse{
		Token:    tokenString,
		TenantID: user.TenantID,
		Role:     user.Role.Name,
	})
}

func AuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized", Message: "Missing or malformed token"})
			c.Abort()
			return
		}

		tokenString = tokenString[7:]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(secret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized", Message: "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized", Message: "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("tenant_id", claims["tenant_id"])
		c.Set("role", claims["role"])
		c.Next()
	}
}

func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized", Message: "Role not found"})
			c.Abort()
			return
		}

		for _, allowed := range allowedRoles {
			if role == allowed {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, models.APIError{Error: "Forbidden", Message: "Insufficient permissions"})
		c.Abort()
	}
}
