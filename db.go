package main

import (
	"os"
	"time"

	"gorm.io/driver/mysql"
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
	var driver gorm.Dialector
	DBtype := get(os.Getenv("TINY_AUTH_SERVICE_DATABASE_TYPE"), "sqlite3")
	if DBtype == "sqlite3" {
		driver = sqlite.Open("users.db")
	} else if DBtype == "mysql" || DBtype == "mariadb" {
		driver = mysql.Open(os.Getenv("TINY_AUTH_SERVICE_DATABASE_DSN"))
	}
	db, _ = gorm.Open(driver, &gorm.Config{})
	db.AutoMigrate(&user{})
}
