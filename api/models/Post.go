package models

import (
	"errors"
	"html"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

// Структура статьи
type Post struct {
	ID        uint64    `gorm:"primary_key;auto_increment" json:"id"`        // Уникальный идентификатор
	Title     string    `gorm:"size:255;not null;unique" json:"title"`       // Название статьи
	Content   string    `gorm:"size:255;not null;" json:"content"`           // Содержание статьи
	Author    User      `json:"author"`                                      // Автор статьи
	AuthorID  uint32    `gorm:"not null" json:"author_id"`                   // Уникальный идентификатор автора статьи
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"` // Дата создания
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"` // Дата изменения
}

func (p *Post) Prepare() {
	p.ID = 0
	p.Title = html.EscapeString(strings.TrimSpace(p.Title))
	p.Content = html.EscapeString(strings.TrimSpace(p.Content))
	p.Author = User{}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
}

func (p *Post) Validate() error {
	// Функция валидации полей статьи

	if p.Title == "" {
		return errors.New("required Title")
	}
	if p.Content == "" {
		return errors.New("required Content")
	}
	if p.AuthorID < 1 {
		return errors.New("required Author")
	}
	return nil
}

func (p *Post) SavePost(db *gorm.DB) (*Post, error) {
	// Функция создания новой статьи в БД

	var err error
	err = db.Debug().Model(&Post{}).Create(&p).Error
	if err != nil {
		return &Post{}, err
	}
	if p.ID != 0 {
		err = db.Debug().Model(&User{}).Where("id = ?", p.AuthorID).Take(&p.Author).Error
		if err != nil {
			return &Post{}, err
		}
	}
	return p, nil
}

func (p *Post) FindAllPosts(db *gorm.DB) (*[]Post, error) {
	// Функция извлечения всех статей из БД

	var err error
	posts := []Post{}
	err = db.Debug().Model(&Post{}).Limit(100).Find(&posts).Error
	if err != nil {
		return &[]Post{}, err
	}
	if len(posts) > 0 {
		for i, _ := range posts {
			err := db.Debug().Model(&User{}).Where("id = ?", posts[i].AuthorID).Take(&posts[i].Author).Error
			if err != nil {
				return &[]Post{}, err
			}
		}
	}
	return &posts, nil
}

func (p *Post) FindPostByID(db *gorm.DB, pid uint64) (*Post, error) {
	// Функция извлечения статьи по ID из БД

	var err error
	err = db.Debug().Model(&Post{}).Where("id = ?", pid).Take(&p).Error
	if err != nil {
		return &Post{}, err
	}
	if p.ID != 0 {
		err = db.Debug().Model(&User{}).Where("id = ?", p.AuthorID).Take(&p.Author).Error
		if err != nil {
			return &Post{}, err
		}
	}
	return p, nil
}

func (p *Post) UpdateAPost(db *gorm.DB) (*Post, error) {
	// Функция обновления данных статьи в БД
	var err error

	err = db.Debug().Model(&Post{}).Where("id = ?", p.ID).Updates(Post{Title: p.Title, Content: p.Content, UpdatedAt: time.Now()}).Error
	if err != nil {
		return &Post{}, err
	}
	if p.ID != 0 {
		err = db.Debug().Model(&User{}).Where("id = ?", p.AuthorID).Take(&p.Author).Error
		if err != nil {
			return &Post{}, err
		}
	}
	return p, nil
}

func (p *Post) DeleteAPost(db *gorm.DB, pid uint64, uid uint32) (int64, error) {
	// Функция удаления статьи из БД

	db = db.Debug().Model(&Post{}).Where("id = ? and author_id = ?", pid, uid).Take(&Post{}).Delete(&Post{})

	if db.Error != nil {
		if gorm.IsRecordNotFoundError(db.Error) {
			return 0, errors.New("Post not found")
		}
		return 0, db.Error
	}
	return db.RowsAffected, nil
}
