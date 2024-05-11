package models

import (
	"errors"
	"html"
	"log"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// Структура пользователя
type User struct {
	ID        uint32    `gorm:"primary_key;auto_increment" json:"id"`        // Уникальный идентификатор
	Nickname  string    `gorm:"size:255;not null;unique" json:"nickname"`    // Псевдоним пользователя
	Email     string    `gorm:"size:100;not null;unique" json:"email"`       // Адрес электронной почты
	Password  string    `gorm:"size:100;not null;" json:"password"`          // Пароль
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"` // Дата создания
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"` // Дата изменения
}

func Hash(password string) ([]byte, error) {
	// Создает хэш из пароля
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (u *User) BeforeSave() error {
	hashedPassword, err := Hash(u.Password)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *User) Prepare() {
	u.ID = 0
	u.Nickname = html.EscapeString(strings.TrimSpace(u.Nickname))
	u.Email = html.EscapeString(strings.TrimSpace(u.Email))
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
}

func (u *User) Validate(action string) error {
	// Функция валидации полей пользователя при изменении данных и при авторизации

	switch strings.ToLower(action) {
	case "update":
		if u.Nickname == "" {
			return errors.New("required Nickname")
		}
		if u.Password == "" {
			return errors.New("required Password")
		}
		if u.Email == "" {
			return errors.New("required Email")
		}
		if err := checkmail.ValidateFormat(u.Email); err != nil {
			return errors.New("invalid Email")
		}

		return nil
	case "login":
		if u.Password == "" {
			return errors.New("required Password")
		}
		if u.Email == "" {
			return errors.New("required Email")
		}
		if err := checkmail.ValidateFormat(u.Email); err != nil {
			return errors.New("invalid Email")
		}
		return nil

	default:
		if u.Nickname == "" {
			return errors.New("required Nickname")
		}
		if u.Password == "" {
			return errors.New("required Password")
		}
		if u.Email == "" {
			return errors.New("required Email")
		}
		if err := checkmail.ValidateFormat(u.Email); err != nil {
			return errors.New("invalid Email")
		}
		return nil
	}
}

func (u *User) SaveUser(db *gorm.DB) (*User, error) {
	// Функция создания нового пользователя в БД

	err := db.Debug().Create(&u).Error

	// Обрабатываем ошибку
	if err != nil {
		return &User{}, err
	}
	return u, nil
}

func (u *User) FindAllUsers(db *gorm.DB) (*[]User, error) {
	// Функция извлечения всех пользователей из БД

	var err error
	users := []User{}
	err = db.Debug().Model(&User{}).Limit(100).Find(&users).Error

	// Обрабатываем ошибку
	if err != nil {
		return &[]User{}, err
	}
	return &users, err
}

func (u *User) FindUserByID(db *gorm.DB, uid uint32) (*User, error) {
	// Функция извлечения пользователя по ID из БД

	err := db.Debug().Model(User{}).Where("id = ?", uid).Take(&u).Error

	// Обрабатываем ошибку
	if err != nil {
		return &User{}, err
	}
	// Проверяем вид ошибки
	if gorm.IsRecordNotFoundError(err) {
		return &User{}, errors.New("пользователь в БД не обнаружен")
	}
	return u, err
}

func (u *User) UpdateAUser(db *gorm.DB, uid uint32) (*User, error) {
	// Функция обновления  данных пользователя в БД

	err := u.BeforeSave() // Хэшируем пароль
	if err != nil {
		log.Fatal(err)
	}

	// Делаем запрос на изменение полей
	db = db.Debug().Model(&User{}).Where("id = ?", uid).Take(&User{}).UpdateColumns(
		map[string]interface{}{
			"password":  u.Password,
			"nickname":  u.Nickname,
			"email":     u.Email,
			"update_at": time.Now(),
		},
	)
	if db.Error != nil {
		return &User{}, db.Error
	}

	// Делаем запрос на извлечение данных пользователя
	err = db.Debug().Model(&User{}).Where("id = ?", uid).Take(&u).Error
	if err != nil {
		return &User{}, err
	}
	return u, nil
}

func (u *User) DeleteAUser(db *gorm.DB, uid uint32) (int64, error) {
	// Функция удаления пользователя из БД

	db = db.Debug().Model(&User{}).Where("id = ?", uid).Take(&User{}).Delete(&User{})

	if db.Error != nil {
		return 0, db.Error
	}
	return db.RowsAffected, nil
}
