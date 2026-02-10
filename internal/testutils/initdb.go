package testutils

import (
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/khanghh/kauth/model"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	db   *gorm.DB
	once sync.Once
)

func MustInitDatabase() *gorm.DB {
	once.Do(func() {
		var (
			err error
			dsn = os.Getenv("DB_URL")
		)

		if dsn != "" {
			db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		} else {
			db, err = gorm.Open(
				sqlite.Open("file::memory:?cache=shared"),
				&gorm.Config{},
			)
		}

		if err != nil {
			panic(err)
		}

		if sqlDB, err := db.DB(); err == nil {
			sqlDB.SetMaxOpenConns(10)
			sqlDB.SetMaxIdleConns(5)
			sqlDB.SetConnMaxLifetime(time.Hour)
		}

		if err := db.AutoMigrate(model.Models...); err != nil {
			slog.Error("Database migration failed", "error", err)
			os.Exit(1)
		}
	})

	return db
}
