package homepage

import (
	"net/http"
	"strconv"
	"strings"
)

// The pages are shown in ONE language: the one in the lang cookie, else the one
// Accept-Language prefers among the seven below, else French. The same seven
// languages, codes and cookie names as go-authn/bridge's pages (bridge#104).
// The German, Spanish, Japanese, Korean and Chinese texts were written without
// a native review: corrections are welcome.
const (
	langFR = "fr"
	langEN = "en"
	langDE = "de"
	langES = "es"
	langJA = "ja"
	langKO = "ko"
	langZH = "zh-cn"

	langCookie  = "lang"
	themeCookie = "theme"

	themeLight  = "light"
	themeDark   = "dark"
	themeSystem = "system"
)

// language is a language a page can be in: the code of the cookie and of the
// /lang route, the BCP 47 tag of <html lang>, and its name in itself.
type language struct{ Code, Tag, Name string }

var languages = []language{
	{langFR, "fr", "Français"},
	{langEN, "en", "English"},
	{langDE, "de", "Deutsch"},
	{langES, "es", "Español"},
	{langJA, "ja", "日本語"},
	{langKO, "ko", "한국어"},
	{langZH, "zh-CN", "简体中文"},
}

func isLang(code string) bool {
	for _, l := range languages {
		if l.Code == code {
			return true
		}
	}
	return false
}

func langTag(code string) string {
	for _, l := range languages {
		if l.Code == code {
			return l.Tag
		}
	}
	return "fr"
}

func isTheme(v string) bool { return v == themeLight || v == themeDark || v == themeSystem }

func chooseTheme(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && isTheme(c.Value) {
		return c.Value
	}
	return themeSystem
}

// matchLang is the language of an Accept-Language range (lower case): the seven
// languages by their primary subtag, any zh-* as zh-cn.
func matchLang(tag string) (string, bool) {
	primary, _, _ := strings.Cut(tag, "-")
	if primary == "zh" {
		return langZH, true
	}
	if primary != langZH && isLang(primary) {
		return primary, true
	}
	return "", false
}

// chooseLang: the cookie, then Accept-Language (RFC 9110 12.5.4: the highest q,
// the first on a tie), then French.
func chooseLang(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && isLang(c.Value) {
		return c.Value
	}
	h := r.Header.Get("Accept-Language")
	if len(h) > 300 {
		h = h[:300]
	}
	best, bestQ := langFR, 0.0
	for _, part := range strings.Split(h, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		primary, ok := matchLang(strings.ToLower(strings.TrimSpace(tag)))
		if !ok {
			continue
		}
		q := 1.0
		if p := strings.TrimSpace(params); strings.HasPrefix(strings.ToLower(p), "q=") {
			v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64)
			if err != nil || v < 0 || v > 1 {
				continue
			}
			q = v
		}
		if q > bestQ {
			best, bestQ = primary, q
		}
	}
	return best
}

// catalogue: language -> key -> text. Every key exists in all seven languages
// (TestCatalogueIsComplete); a template naming a missing key is an error, not
// a blank.
var catalogue = map[string]map[string]string{
	langFR: {
		"skip":         "Aller au contenu",
		"lang.nav":     "Langue",
		"lang.go":      "Valider",
		"theme.nav":    "Thème d'affichage",
		"theme.light":  "Clair",
		"theme.dark":   "Sombre",
		"theme.system": "Système",

		"collab.title":      "Collaboration",
		"collab.h1":         "Collaboration en direct",
		"collab.lead":       "Ce service est le point de rendez-vous et de session de la collaboration pair à pair dans le playground go-tex.",
		"collab.up":         "Service en ligne",
		"collab.how.h":      "Comment ça marche",
		"collab.how.1":      "Une personne se connecte et ouvre la session : c'est l'hôte.",
		"collab.how.2":      "Les invités rejoignent la session par un lien ou un code QR.",
		"collab.how.3":      "L'hôte admet chaque invité avant qu'il ne participe.",
		"collab.direct":     "Les échanges passent directement d'un participant à l'autre, ou par le relais quand ce n'est pas possible.",
		"collab.playground": "Ouvrir le playground",
		"collab.signinhint": "L'hôte se connecte depuis le playground, qui ouvre la fenêtre de connexion.",

		"turn.title":        "Relais STUN/TURN",
		"turn.h1":           "Relais STUN/TURN",
		"turn.lead":         "Ce serveur relaie le trafic de la collaboration go-tex lorsque deux participants ne peuvent pas se joindre directement, par exemple derrière un pare-feu ou un NAT strict.",
		"turn.transports.h": "Transports proposés",
		"turn.port":         "port %s",
		"turn.notweb":       "Ce n'est pas un service web à parcourir : les clients s'y connectent automatiquement, avec des identifiants temporaires.",
		"turn.collab":       "Page de la collaboration",
	},
	langEN: {
		"skip":         "Skip to content",
		"lang.nav":     "Language",
		"lang.go":      "Apply",
		"theme.nav":    "Colour theme",
		"theme.light":  "Light",
		"theme.dark":   "Dark",
		"theme.system": "System",

		"collab.title":      "Collaboration",
		"collab.h1":         "Live collaboration",
		"collab.lead":       "This service is the rendezvous and session service for peer-to-peer collaboration in the go-tex playground.",
		"collab.up":         "Service up",
		"collab.how.h":      "How it works",
		"collab.how.1":      "One person signs in and opens the session: the host.",
		"collab.how.2":      "Guests join the session by a link or a QR code.",
		"collab.how.3":      "The host admits each guest before they take part.",
		"collab.direct":     "Traffic goes directly from one participant to another, or through the relay when it cannot.",
		"collab.playground": "Open the playground",
		"collab.signinhint": "The host signs in from the playground, which opens the sign-in window.",

		"turn.title":        "STUN/TURN relay",
		"turn.h1":           "STUN/TURN relay",
		"turn.lead":         "This server relays go-tex collaboration traffic when two participants cannot reach each other directly, for example behind a firewall or a strict NAT.",
		"turn.transports.h": "Transports offered",
		"turn.port":         "port %s",
		"turn.notweb":       "This is not a web service to browse: clients connect to it automatically, with temporary credentials.",
		"turn.collab":       "Collaboration page",
	},
	langDE: {
		"skip":         "Zum Inhalt springen",
		"lang.nav":     "Sprache",
		"lang.go":      "Übernehmen",
		"theme.nav":    "Darstellung ändern",
		"theme.light":  "Hell",
		"theme.dark":   "Dunkel",
		"theme.system": "System",

		"collab.title":      "Zusammenarbeit",
		"collab.h1":         "Zusammenarbeit in Echtzeit",
		"collab.lead":       "Dieser Dienst ist der Treffpunkt- und Sitzungsdienst für die Peer-to-Peer-Zusammenarbeit im go-tex-Playground.",
		"collab.up":         "Dienst online",
		"collab.how.h":      "So funktioniert es",
		"collab.how.1":      "Eine Person meldet sich an und eröffnet die Sitzung: der Host.",
		"collab.how.2":      "Gäste treten der Sitzung über einen Link oder einen QR-Code bei.",
		"collab.how.3":      "Der Host lässt jeden Gast zu, bevor er teilnimmt.",
		"collab.direct":     "Der Datenverkehr läuft direkt von Teilnehmer zu Teilnehmer, oder über das Relay, wenn das nicht möglich ist.",
		"collab.playground": "Playground öffnen",
		"collab.signinhint": "Der Host meldet sich im Playground an, das das Anmeldefenster öffnet.",

		"turn.title":        "STUN/TURN-Relay",
		"turn.h1":           "STUN/TURN-Relay",
		"turn.lead":         "Dieser Server leitet den Datenverkehr der go-tex-Zusammenarbeit weiter, wenn zwei Teilnehmer sich nicht direkt erreichen können, etwa hinter einer Firewall oder einem strikten NAT.",
		"turn.transports.h": "Angebotene Transporte",
		"turn.port":         "Port %s",
		"turn.notweb":       "Dies ist kein Webdienst zum Durchsuchen: Clients verbinden sich automatisch mit temporären Zugangsdaten.",
		"turn.collab":       "Seite der Zusammenarbeit",
	},
	langES: {
		"skip":         "Saltar al contenido",
		"lang.nav":     "Idioma",
		"lang.go":      "Aplicar",
		"theme.nav":    "Cambiar tema",
		"theme.light":  "Claro",
		"theme.dark":   "Oscuro",
		"theme.system": "Sistema",

		"collab.title":      "Colaboración",
		"collab.h1":         "Colaboración en directo",
		"collab.lead":       "Este servicio es el punto de encuentro y de sesión de la colaboración de igual a igual en el playground de go-tex.",
		"collab.up":         "Servicio en línea",
		"collab.how.h":      "Cómo funciona",
		"collab.how.1":      "Una persona inicia sesión y abre la sesión de colaboración: el anfitrión.",
		"collab.how.2":      "Los invitados se unen a la sesión mediante un enlace o un código QR.",
		"collab.how.3":      "El anfitrión admite a cada invitado antes de que participe.",
		"collab.direct":     "El tráfico pasa directamente de un participante a otro, o por el relé cuando no es posible.",
		"collab.playground": "Abrir el playground",
		"collab.signinhint": "El anfitrión inicia sesión desde el playground, que abre la ventana de inicio de sesión.",

		"turn.title":        "Relé STUN/TURN",
		"turn.h1":           "Relé STUN/TURN",
		"turn.lead":         "Este servidor retransmite el tráfico de la colaboración de go-tex cuando dos participantes no pueden comunicarse directamente, por ejemplo detrás de un cortafuegos o de un NAT estricto.",
		"turn.transports.h": "Transportes ofrecidos",
		"turn.port":         "puerto %s",
		"turn.notweb":       "No es un servicio web para navegar: los clientes se conectan automáticamente, con credenciales temporales.",
		"turn.collab":       "Página de la colaboración",
	},
	langJA: {
		"skip":         "本文へスキップ",
		"lang.nav":     "言語",
		"lang.go":      "適用",
		"theme.nav":    "テーマを変更",
		"theme.light":  "ライト",
		"theme.dark":   "ダーク",
		"theme.system": "システム",

		"collab.title":      "共同編集",
		"collab.h1":         "リアルタイム共同編集",
		"collab.lead":       "このサービスは、go-tex プレイグラウンドでのピアツーピア共同編集のための待ち合わせとセッションを担います。",
		"collab.up":         "稼働中",
		"collab.how.h":      "しくみ",
		"collab.how.1":      "ひとりがサインインしてセッションを開きます。これがホストです。",
		"collab.how.2":      "ゲストはリンクまたは QR コードでセッションに参加します。",
		"collab.how.3":      "ホストが各ゲストの参加を承認します。",
		"collab.direct":     "通信は参加者どうしで直接行われ、直接つながらない場合はリレーを経由します。",
		"collab.playground": "プレイグラウンドを開く",
		"collab.signinhint": "ホストはプレイグラウンドからサインインします。サインイン用のウィンドウはプレイグラウンドが開きます。",

		"turn.title":        "STUN/TURN リレー",
		"turn.h1":           "STUN/TURN リレー",
		"turn.lead":         "このサーバーは、ファイアウォールや厳しい NAT の内側などで参加者どうしが直接つながれないとき、go-tex の共同編集の通信を中継します。",
		"turn.transports.h": "提供するトランスポート",
		"turn.port":         "ポート %s",
		"turn.notweb":       "ブラウザで閲覧するための Web サービスではありません。クライアントが一時的な認証情報で自動的に接続します。",
		"turn.collab":       "共同編集のページ",
	},
	langKO: {
		"skip":         "본문으로 건너뛰기",
		"lang.nav":     "언어",
		"lang.go":      "적용",
		"theme.nav":    "테마 변경",
		"theme.light":  "밝은 테마",
		"theme.dark":   "어두운 테마",
		"theme.system": "시스템",

		"collab.title":      "공동 작업",
		"collab.h1":         "실시간 공동 작업",
		"collab.lead":       "이 서비스는 go-tex 플레이그라운드의 피어 투 피어 공동 작업을 위한 만남과 세션을 맡습니다.",
		"collab.up":         "서비스 정상",
		"collab.how.h":      "작동 방식",
		"collab.how.1":      "한 사람이 로그인해 세션을 엽니다. 이 사람이 호스트입니다.",
		"collab.how.2":      "게스트는 링크나 QR 코드로 세션에 참여합니다.",
		"collab.how.3":      "호스트가 각 게스트의 참여를 승인합니다.",
		"collab.direct":     "통신은 참가자끼리 직접 오가며, 직접 연결할 수 없을 때는 릴레이를 거칩니다.",
		"collab.playground": "플레이그라운드 열기",
		"collab.signinhint": "호스트는 플레이그라운드에서 로그인하며, 로그인 창은 플레이그라운드가 엽니다.",

		"turn.title":        "STUN/TURN 릴레이",
		"turn.h1":           "STUN/TURN 릴레이",
		"turn.lead":         "이 서버는 방화벽이나 엄격한 NAT 뒤에 있는 등 두 참가자가 직접 연결할 수 없을 때 go-tex 공동 작업의 트래픽을 중계합니다.",
		"turn.transports.h": "제공하는 전송 방식",
		"turn.port":         "포트 %s",
		"turn.notweb":       "둘러보는 웹 서비스가 아닙니다. 클라이언트가 임시 자격 증명으로 자동 접속합니다.",
		"turn.collab":       "공동 작업 페이지",
	},
	langZH: {
		"skip":         "跳到正文",
		"lang.nav":     "语言",
		"lang.go":      "应用",
		"theme.nav":    "切换主题",
		"theme.light":  "浅色",
		"theme.dark":   "深色",
		"theme.system": "跟随系统",

		"collab.title":      "协作",
		"collab.h1":         "实时协作",
		"collab.lead":       "本服务是 go-tex 在线编辑器中点对点协作的会合与会话服务。",
		"collab.up":         "服务正常",
		"collab.how.h":      "工作方式",
		"collab.how.1":      "一人登录并开启会话，即为主持人。",
		"collab.how.2":      "访客通过链接或二维码加入会话。",
		"collab.how.3":      "主持人先批准每位访客，访客才能参与。",
		"collab.direct":     "数据在参与者之间直接传输；无法直连时经由中继转发。",
		"collab.playground": "打开在线编辑器",
		"collab.signinhint": "主持人在在线编辑器中登录，登录窗口由在线编辑器打开。",

		"turn.title":        "STUN/TURN 中继",
		"turn.h1":           "STUN/TURN 中继",
		"turn.lead":         "当两位参与者无法直接互通时（例如处于防火墙或严格的 NAT 之后），本服务器负责中继 go-tex 协作的流量。",
		"turn.transports.h": "提供的传输方式",
		"turn.port":         "端口 %s",
		"turn.notweb":       "这不是供浏览的网站：客户端使用临时凭据自动连接。",
		"turn.collab":       "协作页面",
	},
}

func lookup(lang, key string) (string, bool) {
	s, ok := catalogue[lang][key]
	return s, ok && s != ""
}
