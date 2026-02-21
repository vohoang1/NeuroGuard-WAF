package models

import (
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name      string    `json:"name" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Role struct {
	ID   int    `json:"id" gorm:"primary_key"`
	Name string `json:"name" gorm:"unique;not null"`
}

type User struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	TenantID     uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null"`
	Username     string    `json:"username" gorm:"unique;not null"`
	PasswordHash string    `json:"-" gorm:"not null"`
	RoleID       int       `json:"role_id" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	Tenant Tenant `gorm:"foreignKey:TenantID"`
	Role   Role   `gorm:"foreignKey:RoleID"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token    string    `json:"token"`
	TenantID uuid.UUID `json:"tenant_id"`
	Role     string    `json:"role"`
}

type WafLog struct {
	TenantID      string    `json:"tenant_id"`
	Timestamp     time.Time `json:"timestamp"`
	CorrelationID string    `json:"correlation_id"`
	SourceIP      string    `json:"source_ip"`
	Method        string    `json:"method"`
	URI           string    `json:"uri"`
	AttackType    string    `json:"attack_type"`
	Confidence    float32   `json:"confidence"`
	RuleID        *int      `json:"rule_id,omitempty"`
	Action        string    `json:"action"`
	UserAgent     string    `json:"user_agent"`
	CountryCode   string    `json:"country_code"`
	AiScore       float32   `json:"ai_score"`
}

type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
