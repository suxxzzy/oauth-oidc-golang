package authorizationserver

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/ory/fosite"
	//"net/http"
	"time"

	"github.com/ory/fosite/compose"
	//"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	//"github.com/ory/fosite/token/jwt"
)

//oauth+oidc 인증 서버 설정하고 빌드하는 코드입니다.

var(
	config = &compose.Config{
		AccessTokenLifespan: time.Minute * 10, //10분
		RefreshTokenLifespan: time.Minute * 60 * 24 * 14, //2주
		AuthorizeCodeLifespan: time.Minute * 5, //5분
		IDTokenLifespan: time.Minute * 10, //10분
		IDTokenIssuer: "trustnhope",
		DisableRefreshTokenValidation: false, //리프레시 토큰 검증 비활성화 취소
		EnforcePKCE: true, //PKCE를 통한 authcode 인터셉트 공격방지
		EnforcePKCEForPublicClients: true,
		//RedirectSecureChecker:
		UseLegacyErrorFormat: true, //로그인 에러 보여주기
	}

	//여기가 문제임ㅠ
	TNHSSOMemoryStore = &storage.MemoryStore{
		IDSessions: make(map[string]fosite.Requester),
		Clients: map[string]fosite.Client{
			"service1": &fosite.DefaultClient{
				ID:             "my-client",
				Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
				RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
				RedirectURIs:   []string{"http://vegas-solution.com/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"fosite", "openid", "photos", "offline"},
			},
			"service2": &fosite.DefaultClient{
				ID:             "encoded:client",
				Secret:         []byte(`$2a$10$A7M8b65dSSKGHF0H2sNkn.9Z0hT8U1Nv6OWPV3teUUaczXkVkxuDS`), // = "encoded&password"
				RotatedSecrets: nil,
				RedirectURIs:   []string{"http://hanchartcloud.com/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"fosite", "openid", "photos", "offline"},
			},
		},
		Users: map[string]storage.MemoryUserRelation{
			"suhyun": {
				// This store simply checks for equality, a real storage implementation would obviously use
				// a hashing algorithm for encrypting the user password.
				Username: "suhyun",
				Password: "secret",
			},
		},
		AuthorizeCodes:         map[string]storage.StoreAuthorizeCode{},
		AccessTokens:           map[string]fosite.Requester{},
		RefreshTokens:          map[string]storage.StoreRefreshToken{},
		PKCES:                  map[string]fosite.Requester{},
		AccessTokenRequestIDs:  map[string]string{},
		RefreshTokenRequestIDs: map[string]string{},
		IssuerPublicKeys:       map[string]storage.IssuerPublicKeys{},
	}
	
	//클라이언트 아이디와 시크릿, 사용자 계정 정보 저장:: 커스텀하게 어떻게 등록해ㅠㅠ??
	store = storage.NewMemoryStore()

	//액세스 및 리프레시 토큰 및 auth code를 생성하기 위해 사용되는 시크릿 키.
	//반드시 글자수는 공백 포함 32자여야한다.
	secret = []byte("but i`m to late to make you mine")

	//jwt토큰에 서명할 때 사용되는 비밀키 기본값으로 RS256(RSA Signature with SHA-256)
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

var oauth2 = compose.ComposeAllEnabled(config, store, secret, privateKey)// 두번째 인자에는 무슨 타입을 넣어도 상관이없다! 그치만 규칙은 지켜야제.