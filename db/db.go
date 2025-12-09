package db

import (
	"fmt"
	"log"
	"os"

	model "postit/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Dbconnect() {

	value := os.Getenv("DB_PASSWORD")
	dsn := value
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	sqldb, err := DB.DB()
	if err != nil {
		log.Fatalf("Failed to get db object:%v", err)

	}

	if err := sqldb.Ping(); err != nil {
		log.Fatalf("failed to ping the db:%v", err)
	}

	fmt.Printf("successfully connected to the database")

	err = DB.AutoMigrate(&model.User{}, &model.Post{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	fmt.Println("Database migrated successfully!")
}
