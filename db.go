package main

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type user struct {
	gorm.Model
	Username   string `gorm:"primaryKey" gorm:"index"`
	PassHash   string
	Salt       string
	LastSignin time.Time
	Created    int64 `gorm:"autoCreateTime"`
	ACLS       string
}

var db *gorm.DB

func dbConnect() {
	db, _ = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	db.AutoMigrate(&user{})
}
