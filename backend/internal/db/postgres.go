package db

import (
	"log"

	"neuroguard-api/internal/config"
	"neuroguard-api/internal/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitPostgres(cfg *config.Config) {
	var err error
	DB, err = gorm.Open(postgres.Open(cfg.PostgresDSN), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// AutoMigrate the schema
	err = DB.AutoMigrate(&models.Tenant{}, &models.Role{}, &models.User{})
	if err != nil {
		log.Fatalf("Failed to migrate PostgreSQL schema: %v", err)
	}

	seedInitialData()
	log.Println("Successfully connected to PostgreSQL database and verified schema!")
}

func seedInitialData() {
	var count int64

	// Seed Roles
	DB.Model(&models.Role{}).Count(&count)
	if count == 0 {
		roles := []models.Role{
			{ID: 1, Name: "Admin"},
			{ID: 2, Name: "Analyst"},
			{ID: 3, Name: "Viewer"},
		}
		DB.Create(&roles)
		log.Println("Seeded Roles.")
	}

	// Seed Tech Corp Organization
	DB.Model(&models.Tenant{}).Count(&count)
	if count == 0 {
		tenant1 := models.Tenant{Name: "Tech Corp"}
		tenant2 := models.Tenant{Name: "Cyber Dynamics"}
		DB.Create(&tenant1)
		DB.Create(&tenant2)
		log.Println("Seeded Tenants: Tech Corp, Cyber Dynamics.")

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		
		users := []models.User{
			{
				TenantID:     tenant1.ID,
				Username:     "admin",
				PasswordHash: string(hashedPassword),
				RoleID:       1, // Admin (Tech Corp)
			},
			{
				TenantID:     tenant1.ID,
				Username:     "viewer",
				PasswordHash: string(hashedPassword),
				RoleID:       3, // Viewer (Tech Corp)
			},
			{
				TenantID:     tenant2.ID,
				Username:     "cyberadmin",
				PasswordHash: string(hashedPassword),
				RoleID:       1, // Admin (Cyber Dynamics)
			},
		}
		DB.Create(&users)
		log.Println("Seeded Users: admin, viewer, cyberadmin.")
	}
}
