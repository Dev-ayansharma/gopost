package model

import (
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	Name      string         `gorm:"size:255;not null"`
	Email     string         `gorm:"size:255;not null;uniqueIndex"`
	Posts     []Post         `gorm:"foreignKey:UserID"`
	Password  string
}

// Post represents a blog post
type Post struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	Title     string         `gorm:"size:255;not null"`
	Content   string         `gorm:"type:text"`
	UserID    uint           `gorm:"not null"`
	User      User           `gorm:"foreignKey:UserID"`
	Image     string
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if !strings.HasPrefix(u.Password, "$2a$") { // if not already hashed
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.Password = string(hash)
	}
	return nil
}
