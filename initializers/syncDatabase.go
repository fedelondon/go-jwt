package initializers

import "go-jwt/models"

func SyncDatabase() {
	if err := DB.AutoMigrate(&models.User{}); err != nil {
		panic(err)
	}
}
