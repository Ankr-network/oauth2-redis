package redis

import (
	"github.com/Ankr-network/kit/auth"
	"testing"
	"time"

	"github.com/go-redis/redis"
	"gopkg.in/oauth2.v3/models"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	addr = "localhost:6379"
	db   = 1
)

func TestTokenStore(t *testing.T) {
	Convey("Test redis token store", t, func() {
		opts := &redis.Options{
			Addr: addr,
			DB:   db,
		}
		store := NewRedisTokenStore(redis.NewClient(opts))

		Convey("Test authorization code store", func() {
			info := &models.Token{
				ClientID:      "1",
				UserID:        "1_1",
				RedirectURI:   "http://localhost/",
				Scope:         "all",
				Code:          "11_11_11",
				CodeCreateAt:  time.Now(),
				CodeExpiresIn: time.Minute * 5,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			cInfo, err := store.GetByCode(info.Code)
			So(err, ShouldBeNil)
			So(cInfo.GetUserID(), ShouldEqual, info.UserID)

			err = store.RemoveByCode(info.Code)
			So(err, ShouldBeNil)

			cInfo, err = store.GetByCode(info.Code)
			So(err, ShouldBeNil)
			So(cInfo, ShouldBeNil)
		})

		Convey("Test access token store", func() {
			info := &models.Token{
				ClientID:        "1",
				UserID:          "1_1",
				RedirectURI:     "http://localhost/",
				Scope:           "all",
				Access:          "1_1_1",
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 5,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			aInfo, err := store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo.GetUserID(), ShouldEqual, info.GetUserID())

			uInfos, err := store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)
			So(uInfos[0].GetAccess(), ShouldEqual, info.GetAccess())

			err = store.RemoveByAccess(info.GetAccess())
			So(err, ShouldBeNil)

			aInfo, err = store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo, ShouldBeNil)

			uInfos, err = store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldBeEmpty)

			err = store.GetBlacklist().CheckAccess(info.GetAccess())
			So(err, ShouldEqual, auth.ErrExpiredAccess)
		})

		Convey("Test refresh token store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			rInfo, err := store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo.GetUserID(), ShouldEqual, info.GetUserID())
			So(rInfo.GetAccess(), ShouldEqual, info.GetAccess())

			aInfo, err := store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo.GetRefresh(), ShouldEqual, info.GetRefresh())
			So(aInfo.GetUserID(), ShouldEqual, info.GetUserID())

			uInfos, err := store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)
			So(uInfos[0].GetAccess(), ShouldEqual, info.GetAccess())
			So(uInfos[0].GetRefresh(), ShouldEqual, info.GetRefresh())

			err = store.RemoveByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)

			rInfo, err = store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo, ShouldBeNil)

			aInfo, err = store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo, ShouldNotBeNil)

			uInfos, err = store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)

			err = store.GetBlacklist().CheckAccess(info.GetAccess())
			So(err, ShouldBeNil)
		})

		Convey("Test user id store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_3",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_3_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_3_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			uInfos, err := store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)
			So(uInfos[0].GetAccess(), ShouldEqual, info.GetAccess())
			So(uInfos[0].GetRefresh(), ShouldEqual, info.GetRefresh())

			rInfo, err := store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo.GetUserID(), ShouldEqual, info.GetUserID())
			So(rInfo.GetAccess(), ShouldEqual, info.GetAccess())

			aInfo, err := store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo.GetRefresh(), ShouldEqual, info.GetRefresh())
			So(aInfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByUID(info.GetUserID())
			So(err, ShouldBeNil)

			uInfos, err = store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldBeEmpty)

			aInfo, err = store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo, ShouldBeNil)

			rInfo, err = store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo, ShouldBeNil)

			err = store.GetBlacklist().CheckAccess(info.GetAccess())
			So(err, ShouldEqual, auth.ErrExpiredAccess)
		})
	})
}

func TestTokenStoreWithKeyNamespace(t *testing.T) {
	Convey("Test redis token store", t, func() {
		opts := &redis.Options{
			Addr: addr,
			DB:   db,
		}
		store := NewRedisTokenStore(redis.NewClient(opts), WithKeyNamespace("test:"))

		Convey("Test authorization code store", func() {
			info := &models.Token{
				ClientID:      "1",
				UserID:        "1_1",
				RedirectURI:   "http://localhost/",
				Scope:         "all",
				Code:          "11_11_11",
				CodeCreateAt:  time.Now(),
				CodeExpiresIn: time.Second * 5,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			cInfo, err := store.GetByCode(info.Code)
			So(err, ShouldBeNil)
			So(cInfo.GetUserID(), ShouldEqual, info.UserID)

			err = store.RemoveByCode(info.Code)
			So(err, ShouldBeNil)

			cInfo, err = store.GetByCode(info.Code)
			So(err, ShouldBeNil)
			So(cInfo, ShouldBeNil)
		})

		Convey("Test access token store", func() {
			info := &models.Token{
				ClientID:        "1",
				UserID:          "1_1",
				RedirectURI:     "http://localhost/",
				Scope:           "all",
				Access:          "1_1_1",
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 5,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			aInfo, err := store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo.GetUserID(), ShouldEqual, info.GetUserID())

			uInfos, err := store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)
			So(uInfos[0].GetAccess(), ShouldEqual, info.GetAccess())

			err = store.RemoveByAccess(info.GetAccess())
			So(err, ShouldBeNil)

			aInfo, err = store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo, ShouldBeNil)

			uInfos, err = store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldBeEmpty)

			err = store.GetBlacklist().CheckAccess(info.GetAccess())
			So(err, ShouldEqual, auth.ErrExpiredAccess)
		})

		Convey("Test refresh token store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			rInfo, err := store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo.GetUserID(), ShouldEqual, info.GetUserID())
			So(rInfo.GetAccess(), ShouldEqual, info.GetAccess())

			aInfo, err := store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo.GetRefresh(), ShouldEqual, info.GetRefresh())
			So(aInfo.GetUserID(), ShouldEqual, info.GetUserID())

			uInfos, err := store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)
			So(uInfos[0].GetAccess(), ShouldEqual, info.GetAccess())
			So(uInfos[0].GetRefresh(), ShouldEqual, info.GetRefresh())

			err = store.RemoveByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)

			rInfo, err = store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo, ShouldBeNil)

			aInfo, err = store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo, ShouldNotBeNil)

			uInfos, err = store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)

			err = store.GetBlacklist().CheckAccess(info.GetAccess())
			So(err, ShouldBeNil)
		})

		Convey("Test user id store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_3",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_3_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_3_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(info)
			So(err, ShouldBeNil)

			uInfos, err := store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldHaveLength, 1)
			So(uInfos[0].GetAccess(), ShouldEqual, info.GetAccess())
			So(uInfos[0].GetRefresh(), ShouldEqual, info.GetRefresh())

			rInfo, err := store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo.GetUserID(), ShouldEqual, info.GetUserID())
			So(rInfo.GetAccess(), ShouldEqual, info.GetAccess())

			aInfo, err := store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo.GetRefresh(), ShouldEqual, info.GetRefresh())
			So(aInfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByUID(info.GetUserID())
			So(err, ShouldBeNil)

			uInfos, err = store.GetByUID(info.GetUserID())
			So(err, ShouldBeNil)
			So(uInfos, ShouldBeEmpty)

			aInfo, err = store.GetByAccess(info.GetAccess())
			So(err, ShouldBeNil)
			So(aInfo, ShouldBeNil)

			rInfo, err = store.GetByRefresh(info.GetRefresh())
			So(err, ShouldBeNil)
			So(rInfo, ShouldBeNil)

			err = store.GetBlacklist().CheckAccess(info.GetAccess())
			So(err, ShouldEqual, auth.ErrExpiredAccess)
		})
	})
}
