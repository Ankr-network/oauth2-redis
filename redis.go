package redis

import (
	"fmt"
	"time"

	"github.com/Ankr-network/kit/auth"
	"github.com/go-redis/redis"
	jsonIter "github.com/json-iterator/go"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/utils/uuid"
)

var (
	jsonMarshal   = jsonIter.Marshal
	jsonUnmarshal = jsonIter.Unmarshal
)

type Options struct {
	KeyNamespace string
	Blacklist    auth.Blacklist
}

type Option func(opts *Options)

func WithKeyNamespace(ns string) Option {
	return func(opts *Options) {
		opts.KeyNamespace = ns
	}
}

func WithBlacklist(bl auth.Blacklist) Option {
	return func(opts *Options) {
		opts.Blacklist = bl
	}
}

// NewRedisTokenStore create an instance of a redis store with a redis client
func NewRedisTokenStore(cli Client, opts ...Option) *TokenStore {
	cfg := &Options{
		KeyNamespace: "token:",
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.Blacklist == nil {
		cfg.Blacklist = auth.NewRedisBlacklist(cli, auth.WithPrefix(cfg.KeyNamespace+"blacklist:"))
	}

	return &TokenStore{
		cli: cli,
		ns:  cfg.KeyNamespace,
		bl:  cfg.Blacklist,
	}
}

type ExtendedTokenStore interface {
	GetByUID(uid string) ([]oauth2.TokenInfo, error)
	RemoveByUID(uid string) error
	GetBlacklist() auth.Blacklist
	oauth2.TokenStore
}

type Client interface {
	redis.Cmdable
	Close() error
}

// TokenStore redis token store
type TokenStore struct {
	cli Client
	ns  string
	bl  auth.Blacklist
}

// Close close the store
func (s *TokenStore) Close() error {
	return s.cli.Close()
}

func (s *TokenStore) wrapperKey(key string) string {
	return fmt.Sprintf("%s%s", s.ns, key)
}

func (s *TokenStore) checkError(result redis.Cmder) (bool, error) {
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// remove
func (s *TokenStore) remove(key string) error {
	result := s.cli.Del(s.wrapperKey(key))
	_, err := s.checkError(result)
	return err
}

func (s *TokenStore) removeToken(tokenString string, isRefresh bool) error {
	basicID, err := s.getBasicID(tokenString)
	if err != nil {
		return err
	} else if basicID == "" {
		return nil
	}

	err = s.remove(tokenString)
	if err != nil {
		return err
	}

	token, err := s.getToken(basicID)
	if err != nil {
		return err
	} else if token == nil {
		return nil
	}

	if !isRefresh {
		if err := s.bl.PutAccess(tokenString, token.GetAccessCreateAt(), token.GetAccessExpiresIn()); err != nil {
			return err
		}
	}

	checkToken := token.GetRefresh()
	if isRefresh {
		checkToken = token.GetAccess()
	}
	iresult := s.cli.Exists(s.wrapperKey(checkToken))
	if err := iresult.Err(); err != nil && err != redis.Nil {
		return err
	} else if iresult.Val() == 0 {
		// remove uid key

		delResult := s.cli.Del(s.wrapperUIDKey(token.GetUserID(), basicID))
		if _, err := s.checkError(delResult); err != nil {
			return err
		}

		return s.remove(basicID)
	}

	return nil
}

func (s *TokenStore) parseToken(result *redis.StringCmd) (oauth2.TokenInfo, error) {
	if ok, err := s.checkError(result); err != nil {
		return nil, err
	} else if ok {
		return nil, nil
	}

	buf, err := result.Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var token models.Token
	if err := jsonUnmarshal(buf, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *TokenStore) getToken(key string) (oauth2.TokenInfo, error) {
	result := s.cli.Get(s.wrapperKey(key))
	return s.parseToken(result)
}

func (s *TokenStore) parseBasicID(result *redis.StringCmd) (string, error) {
	if ok, err := s.checkError(result); err != nil {
		return "", err
	} else if ok {
		return "", nil
	}
	return result.Val(), nil
}

func (s *TokenStore) getBasicID(token string) (string, error) {
	result := s.cli.Get(s.wrapperKey(token))
	return s.parseBasicID(result)
}

// Create Create and store the new token information
func (s *TokenStore) Create(info oauth2.TokenInfo) error {
	ct := time.Now()
	jv, err := jsonMarshal(info)
	if err != nil {
		return err
	}

	pipe := s.cli.TxPipeline()
	if code := info.GetCode(); code != "" {
		pipe.Set(s.wrapperKey(code), jv, info.GetCodeExpiresIn())
	} else {
		basicID := uuid.Must(uuid.NewRandom()).String()
		aexp := info.GetAccessExpiresIn()
		rexp := aexp

		if refresh := info.GetRefresh(); refresh != "" {
			rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
			if aexp.Seconds() > rexp.Seconds() {
				aexp = rexp
			}
			pipe.Set(s.wrapperKey(refresh), basicID, rexp)
		}

		pipe.Set(s.wrapperUIDKey(info.GetUserID(), basicID), basicID, aexp)
		pipe.Set(s.wrapperKey(info.GetAccess()), basicID, aexp)
		pipe.Set(s.wrapperKey(basicID), jv, rexp)
	}

	if _, err := pipe.Exec(); err != nil {
		return err
	}
	return nil
}

// RemoveByCode Use the authorization code to delete the token information
func (s *TokenStore) RemoveByCode(code string) error {
	return s.remove(code)
}

// RemoveByAccess Use the access token to delete the token information
func (s *TokenStore) RemoveByAccess(access string) error {
	return s.removeToken(access, false)
}

// RemoveByRefresh Use the refresh token to delete the token information
func (s *TokenStore) RemoveByRefresh(refresh string) error {
	return s.removeToken(refresh, true)
}

// GetByCode Use the authorization code for token information data
func (s *TokenStore) GetByCode(code string) (oauth2.TokenInfo, error) {
	return s.getToken(code)
}

// GetByAccess Use the access token for token information data
func (s *TokenStore) GetByAccess(access string) (oauth2.TokenInfo, error) {
	basicID, err := s.getBasicID(access)
	if err != nil || basicID == "" {
		return nil, err
	}
	return s.getToken(basicID)
}

// GetByRefresh Use the refresh token for token information data
func (s *TokenStore) GetByRefresh(refresh string) (oauth2.TokenInfo, error) {
	basicID, err := s.getBasicID(refresh)
	if err != nil || basicID == "" {
		return nil, err
	}
	return s.getToken(basicID)
}

// GetByUID Use the user id for token information data
func (s *TokenStore) GetByUID(uid string) ([]oauth2.TokenInfo, error) {
	var cursor uint64
	var result []oauth2.TokenInfo
	for {
		var keys []string
		var err error
		keys, cursor, err = s.cli.Scan(cursor, s.getUIDKeyPattern(uid), 10).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			basicID, err := s.parseBasicID(s.cli.Get(k))
			if err != nil {
				return nil, err
			}
			token, err := s.getToken(basicID)
			if err != nil {
				return nil, err
			}
			result = append(result, token)
		}
		if cursor == 0 {
			break
		}
	}

	return result, nil
}

// RemoveByUID Use the user id to delete the token information
func (s *TokenStore) RemoveByUID(uid string) error {
	var cursor uint64
	for {
		var keys []string
		var err error
		keys, cursor, err = s.cli.Scan(cursor, s.getUIDKeyPattern(uid), 10).Result()
		if err != nil {
			return err
		}
		for _, k := range keys {
			basicID, err := s.parseBasicID(s.cli.Get(k))
			if err != nil {
				return err
			}

			_, err = s.checkError(s.cli.Del(k))
			if err != nil {
				return err
			}

			token, err := s.getToken(basicID)
			if err != nil {
				return err
			} else if token == nil {
				return nil
			}

			err = s.remove(token.GetRefresh())
			if err != nil {
				return err
			}

			err = s.remove(token.GetAccess())
			if err != nil {
				return err
			}
			if err := s.bl.PutAccess(token.GetAccess(), token.GetAccessCreateAt(), token.GetAccessExpiresIn()); err != nil {
				return err
			}

			err = s.remove(basicID)
			if err != nil {
				return err
			}
		}
		if cursor == 0 {
			break
		}
	}

	return nil
}

func (s *TokenStore) GetBlacklist() auth.Blacklist {
	return s.bl
}

func (s *TokenStore) wrapperUIDKey(uid, basicID string) string {
	return fmt.Sprintf("%suid:%s:%s", s.ns, uid, basicID)
}

func (s *TokenStore) getUIDKeyPattern(uid string) string {
	return fmt.Sprintf("%suid:%s:*", s.ns, uid)
}
