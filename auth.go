package steam

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/0xAozora/go-steam/protocol"
	"github.com/0xAozora/go-steam/protocol/protobuf"
	"github.com/0xAozora/go-steam/protocol/steamlang"
	"github.com/0xAozora/go-steam/steamid"
	"google.golang.org/protobuf/proto"
)

type Auth struct {
	client  *Client
	Details *LogOnDetails

	authSession   *protobuf.CAuthentication_BeginAuthSessionViaCredentials_Response
	Authenticator Authenticator
}

// Custom Authenticator
type Authenticator interface {
	GetCode(protobuf.EAuthSessionGuardType) string
}

type SentryHash []byte

type LogOnDetails struct {
	Username string

	// If logging into an account without a login key, the account's password.
	Password string

	// If you have a Steam Guard email code, you can provide it here.
	AuthCode string

	// If you have a Steam Guard mobile two-factor authentication code, you can provide it here.
	TwoFactorCode  string
	SentryFileHash SentryHash
	LoginKey       string

	// true if you want to get a login key which can be used in lieu of
	// a password for subsequent logins. false or omitted otherwise.
	ShouldRememberPassword bool

	AccessToken  string
	RefreshToken string
	GuardData    string
}

// Log on with the given details. You must always specify username and
// password OR username and loginkey. For the first login, don't set an authcode or a hash and you'll
//
//	receive an error (EResult_AccountLogonDenied)
//
// and Steam will send you an authcode. Then you have to login again, this time with the authcode.
// Shortly after logging in, you'll receive a MachineAuthUpdateEvent with a hash which allows
// you to login without using an authcode in the future.
//
// If you don't use Steam Guard, username and password are enough.
//
// After the event EMsg_ClientNewLoginKey is received you can use the LoginKey
// to login instead of using the password.
func (a *Auth) LogOn(details *LogOnDetails) {
	if details.Username == "" {
		panic("Username must be set!")
	}
	if details.Password == "" && details.LoginKey == "" {
		panic("Password or LoginKey must be set!")
	}

	logon := new(protobuf.CMsgClientLogon)
	logon.AccountName = &details.Username

	if details.RefreshToken != "" {
		logon.AccessToken = &details.RefreshToken // Yes, RefreshToken as AccessToken
	} else {
		logon.Password = &details.Password
		if details.AuthCode != "" {
			logon.AuthCode = proto.String(details.AuthCode)
		}
		if details.TwoFactorCode != "" {
			logon.TwoFactorCode = proto.String(details.TwoFactorCode)
		}

		if details.LoginKey != "" {
			logon.LoginKey = proto.String(details.LoginKey)
		}
	}

	if details.SentryFileHash == nil {
		logon.EresultSentryfile = proto.Int32(9) // NotFound
	} else {
		logon.EresultSentryfile = proto.Int32(1) // OK
	}
	logon.ShaSentryfile = details.SentryFileHash

	if details.ShouldRememberPassword {
		logon.ShouldRememberPassword = proto.Bool(details.ShouldRememberPassword)
	}

	logon.ClientOsType = proto.Uint32(16) // Windows 10
	logon.ClientLanguage = proto.String("english")
	logon.ProtocolVersion = proto.Uint32(steamlang.MsgClientLogon_CurrentProtocol)

	// Other
	logon.CellId = proto.Uint32(5)
	logon.ClientPackageVersion = proto.Uint32(1771)
	logon.SupportsRateLimitResponse = proto.Bool(true)
	logon.MachineName = proto.String("DESKTOP-HELLO")
	logon.MachineId = []byte{
		0, 77, 101, 115, 115, 97, 103, 101, 79, 98, 106, 101, 99, 116, 0, 1, 66, 66, 51, 0, 52, 48, 56, 54, 49, 48, 48, 97, 54, 97, 50, 55, 102, 100, 100, 51, 49, 48, 98, 52, 50, 99, 56, 97, 102, 100, 54, 48, 51, 51, 97, 56, 51, 98, 53, 53, 49, 97, 48, 97, 0, 1, 70, 70, 50, 0, 100, 54, 49, 99, 100, 98, 97, 52, 49, 49, 55, 57, 57, 54, 97, 52, 57, 52, 52, 49, 98, 101, 49, 49, 99, 51, 98, 100, 98, 52, 101, 48, 99, 53, 51, 54, 54, 101, 99, 51, 0, 1, 51, 66, 51, 0, 99, 98, 97, 102, 56, 102, 52, 55, 56, 56, 50, 99, 102, 102, 101, 101, 52, 51, 101, 101, 49, 99, 97, 97, 99, 101, 98, 56, 97, 56, 101, 102, 99, 98, 53, 55, 54, 53, 53, 50, 0, 8, 8,
	}

	logon.ObfuscatedPrivateIp = &protobuf.CMsgIPAddress{Ip: &protobuf.CMsgIPAddress_V4{V4: 2047164953}}
	logon.DeprecatedObfustucatedPrivateIp = proto.Uint32(logon.ObfuscatedPrivateIp.GetV4())

	logon.Steam2TicketRequest = proto.Bool(false)

	atomic.StoreUint64(&a.client.steamId, uint64(steamid.NewIdAdv(0, 1, int32(steamlang.EUniverse_Public), int32(steamlang.EAccountType_Individual))))

	a.client.Send(protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientLogon, logon))
}

func encryptPasword(pwd string, key *protobuf.CAuthentication_GetPasswordRSAPublicKey_Response) (string, error) {

	var n big.Int
	n.SetString(*key.PublickeyMod, 16)

	exp, err := strconv.ParseInt(*key.PublickeyExp, 16, 32)
	if err != nil {
		return "", err
	}

	pub := rsa.PublicKey{N: &n, E: int(exp)}
	rsaOut, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, []byte(pwd))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsaOut), nil
}

func (a *Auth) beginAuthSession(packet *protocol.Packet) error {

	body := new(protobuf.CAuthentication_GetPasswordRSAPublicKey_Response)
	_ = packet.ReadProtoMsg(body)

	crypt, _ := encryptPasword(a.Details.Password, body)

	deviceFriendlyName := "DESKTOP-HELLO"
	platformType := protobuf.EAuthTokenPlatformType_k_EAuthTokenPlatformType_SteamClient.Enum()

	deviceDetails := protobuf.CAuthentication_DeviceDetails{
		DeviceFriendlyName: &deviceFriendlyName,
		PlatformType:       platformType,
		OsType:             proto.Int32(16),
		//GamingDeviceType:   proto.Uint32(1),
	}

	req := protobuf.CAuthentication_BeginAuthSessionViaCredentials_Request{
		// DeviceFriendlyName:  &deviceFriendlyName,
		AccountName:         &a.Details.Username,
		EncryptedPassword:   &crypt,
		EncryptionTimestamp: body.Timestamp,
		// RememberLogin:       proto.Bool(true),
		// PlatformType:        platformType,
		Persistence:   protobuf.ESessionPersistence_k_ESessionPersistence_Persistent.Enum(),
		WebsiteId:     proto.String("Client"),
		DeviceDetails: &deviceDetails,
	}

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ServiceMethodCallFromClientNonAuthed, &req)
	jobname := "Authentication.BeginAuthSessionViaCredentials#1"
	msg.Header.Proto.TargetJobName = &jobname
	jobID := a.client.GetNextJobId()
	msg.SetSourceJobId(jobID) //620515163111425

	a.client.JobMutex.Lock()
	a.client.JobHandlers[uint64(jobID)] = a.handleAuthSession
	a.client.JobMutex.Unlock()

	a.client.Send(msg)

	return nil
}

func (a *Auth) handleAuthSession(packet *protocol.Packet) error {

	body := new(protobuf.CAuthentication_BeginAuthSessionViaCredentials_Response)
	msg := packet.ReadProtoMsg(body)

	_ = msg

	a.authSession = body

	var codeType protobuf.EAuthSessionGuardType
	for _, confirmation := range body.AllowedConfirmations {

		switch *confirmation.ConfirmationType {

		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_None:

			a.pollAuthSession()
			return nil

		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_EmailCode:
			codeType = protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_EmailCode
			fallthrough
		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceCode:
			if codeType == 0 {
				codeType = protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceCode
			}

			go func() {
				var code string
				if a.Authenticator != nil {
					code = a.Authenticator.GetCode(codeType)
				} else {
					fmt.Println("Enter Code:")
					_, _ = fmt.Scanln(&code)
				}
				a.updateAuthSession(code, codeType)
			}()

		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceConfirmation:
			fallthrough
		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_EmailConfirmation:

		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_LegacyMachineAuth:

		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_MachineToken:

		case protobuf.EAuthSessionGuardType_k_EAuthSessionGuardType_Unknown:

		}

	}

	return nil

}

func (a *Auth) updateAuthSession(code string, codeType protobuf.EAuthSessionGuardType) {

	req := protobuf.CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request{
		ClientId: a.authSession.ClientId,
		Steamid:  a.authSession.Steamid,
		Code:     &code,
		CodeType: &codeType,
	}

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ServiceMethodCallFromClientNonAuthed, &req)
	jobname := "Authentication.UpdateAuthSessionWithSteamGuardCode#1"
	msg.Header.Proto.TargetJobName = &jobname
	jobID := a.client.GetNextJobId()
	msg.SetSourceJobId(jobID) //620515163111425

	a.client.JobMutex.Lock()
	a.client.JobHandlers[uint64(jobID)] = a.handleAuthSessionUpdate
	a.client.JobMutex.Unlock()

	a.client.Send(msg)

}

func (a *Auth) handleAuthSessionUpdate(packet *protocol.Packet) error {

	fmt.Println("AuthSession Update")

	body := new(protobuf.CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response)
	_ = packet.ReadProtoMsg(body)

	a.pollAuthSession()
	return nil
}

func (a *Auth) pollAuthSession() {

	req := protobuf.CAuthentication_PollAuthSessionStatus_Request{
		ClientId:  a.authSession.ClientId,
		RequestId: a.authSession.RequestId,
	}

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ServiceMethodCallFromClientNonAuthed, &req)
	jobname := "Authentication.PollAuthSessionStatus#1"
	msg.Header.Proto.TargetJobName = &jobname
	jobID := a.client.GetNextJobId()
	msg.SetSourceJobId(jobID) //620515163111425

	a.client.JobMutex.Lock()
	a.client.JobHandlers[uint64(jobID)] = a.handlePollResponse
	a.client.JobMutex.Unlock()

	a.client.Send(msg)

}

func (a *Auth) handlePollResponse(packet *protocol.Packet) error {

	body := new(protobuf.CAuthentication_PollAuthSessionStatus_Response)
	_ = packet.ReadProtoMsg(body)

	if body.RefreshToken == nil {
		return errors.New("PollError")
	}

	a.Details.AccessToken = *body.AccessToken
	a.Details.RefreshToken = *body.RefreshToken
	if body.NewGuardData != nil {
		a.Details.GuardData = *body.NewGuardData
		fmt.Printf("Guard Data: %s\n", *body.NewGuardData)
	}

	fmt.Printf("Refresh Token: %s\n", *body.RefreshToken)

	a.LogOn(a.Details)
	return nil
}

func (a *Auth) getRSAKey(accountName string) {

	req := new(protobuf.CAuthentication_GetPasswordRSAPublicKey_Request)
	req.AccountName = &accountName

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ServiceMethodCallFromClientNonAuthed, req)
	jobname := "Authentication.GetPasswordRSAPublicKey#1"
	msg.Header.Proto.TargetJobName = &jobname
	jobID := a.client.GetNextJobId()
	msg.SetSourceJobId(jobID) //620515163111425

	a.client.JobMutex.Lock()
	a.client.JobHandlers[uint64(jobID)] = a.beginAuthSession
	a.client.JobMutex.Unlock()

	//msg.SetTargetJobId(protocol.JobId(18446744073709551615))

	a.client.Send(msg)
}

func (a *Auth) LogOnCredentials(details *LogOnDetails) {

	if details.Username == "" {
		panic("Username must be set!")
	}
	if details.Password == "" && details.LoginKey == "" {
		panic("Password or LoginKey must be set!")
	}

	atomic.StoreUint64(&a.client.steamId, uint64(steamid.NewIdAdv(0, 1, int32(steamlang.EUniverse_Public), int32(steamlang.EAccountType_Individual))))

	hello := &protobuf.CMsgClientHello{ProtocolVersion: proto.Uint32(steamlang.MsgClientLogon_CurrentProtocol)}
	a.client.Send(protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientHello, hello))

	time.Sleep(1 * time.Second)
	a.Details = details
	a.getRSAKey(details.Username)
}

func (a *Auth) HandlePacket(packet *protocol.Packet) {
	switch packet.EMsg {
	case steamlang.EMsg_ClientLogOnResponse:
		l, err := a.HandleLogOnResponse(packet)
		if err != nil {
			a.client.Fatalf(err.Error())
		} else if l.Result != steamlang.EResult_OK {
			a.client.Emit(&LogOnFailedEvent{Result: l.Result})
		} else {
			a.client.Emit(l)
		}
	case steamlang.EMsg_ClientNewLoginKey:
		a.client.Emit(a.HandleLoginKey(packet))
	case steamlang.EMsg_ClientSessionToken:
	case steamlang.EMsg_ClientLoggedOff:
		a.client.Emit(a.HandleLoggedOff(packet))
	case steamlang.EMsg_ClientUpdateMachineAuth:
		a.client.Emit(a.HandleUpdateMachineAuth(packet))
	case steamlang.EMsg_ClientAccountInfo:
		a.client.Emit(a.HandleAccountInfo(packet))

	case steamlang.EMsg_ServiceMethodResponse:
		a.client.JobMutex.Lock()
		fn := a.client.JobHandlers[uint64(packet.TargetJobId)]
		delete(a.client.JobHandlers, uint64(packet.TargetJobId))
		a.client.JobMutex.Unlock()
		if err := fn(packet); err != nil {
			a.client.Fatalf(err.Error())
		}
	}
}

func (a *Auth) HandleLogOnResponse(packet *protocol.Packet) (*LoggedOnEvent, error) {
	if !packet.IsProto {
		return nil, errors.New("Got non-proto logon response!")
	}

	body := new(protobuf.CMsgClientLogonResponse)
	msg := packet.ReadProtoMsg(body)

	result := steamlang.EResult(body.GetEresult())
	if result == steamlang.EResult_OK {
		atomic.StoreInt32(&a.client.sessionId, msg.Header.Proto.GetClientSessionid())
		atomic.StoreUint64(&a.client.steamId, msg.Header.Proto.GetSteamid())
		if a.client.Web != nil {
			a.client.Web.webLoginKey = *body.WebapiAuthenticateUserNonce
		}

		go a.client.heartbeatLoop(time.Duration(body.GetHeartbeatSeconds()))

		return &LoggedOnEvent{
			Result:                    steamlang.EResult(body.GetEresult()),
			ExtendedResult:            steamlang.EResult(body.GetEresultExtended()),
			OutOfGameSecsPerHeartbeat: body.GetLegacyOutOfGameHeartbeatSeconds(),
			InGameSecsPerHeartbeat:    body.GetHeartbeatSeconds(),
			PublicIp:                  body.GetDeprecatedPublicIp(),
			ServerTime:                body.GetRtime32ServerTime(),
			AccountFlags:              steamlang.EAccountFlags(body.GetAccountFlags()),
			ClientSteamId:             steamid.SteamId(body.GetClientSuppliedSteamid()),
			EmailDomain:               body.GetEmailDomain(),
			CellId:                    body.GetCellId(),
			CellIdPingThreshold:       body.GetCellIdPingThreshold(),
			Steam2Ticket:              body.GetSteam2Ticket(),
			UsePics:                   body.GetDeprecatedUsePics(),
			WebApiUserNonce:           body.GetWebapiAuthenticateUserNonce(),
			IpCountryCode:             body.GetIpCountryCode(),
			VanityUrl:                 body.GetVanityUrl(),
			NumLoginFailuresToMigrate: body.GetCountLoginfailuresToMigrate(),
			NumDisconnectsToMigrate:   body.GetCountDisconnectsToMigrate(),
		}, nil
	} /*else if result == steamlang.EResult_Fail || result == steamlang.EResult_ServiceUnavailable || result == steamlang.EResult_TryAnotherCM {
		// some error on Steam's side, we'll get an EOF later
	} else {
		a.client.Emit(&LogOnFailedEvent{
			Result: result,
		})
		a.client.Disconnect()
	}*/

	a.client.Disconnect()
	return &LoggedOnEvent{Result: result}, nil
}

func (a *Auth) HandleLoginKey(packet *protocol.Packet) *LoginKeyEvent {
	body := new(protobuf.CMsgClientNewLoginKey)
	packet.ReadProtoMsg(body)
	a.client.Send(protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientNewLoginKeyAccepted, &protobuf.CMsgClientNewLoginKeyAccepted{
		UniqueId: proto.Uint32(body.GetUniqueId()),
	}))
	return &LoginKeyEvent{
		UniqueId: body.GetUniqueId(),
		LoginKey: body.GetLoginKey(),
	}
}

func (a *Auth) HandleLoggedOff(packet *protocol.Packet) *LoggedOffEvent {
	result := steamlang.EResult_Invalid
	var min int32
	if packet.IsProto {
		body := new(protobuf.CMsgClientLoggedOff)
		packet.ReadProtoMsg(body)
		result = steamlang.EResult(body.GetEresult())
	} else {
		body := new(steamlang.MsgClientLoggedOff)
		packet.ReadClientMsg(body)
		result = body.Result
		min = body.SecMinReconnectHint
	}
	return &LoggedOffEvent{Result: result, MinReconnect: min}
}

func (a *Auth) HandleUpdateMachineAuth(packet *protocol.Packet) *MachineAuthUpdateEvent {
	body := new(protobuf.CMsgClientUpdateMachineAuth)
	packet.ReadProtoMsg(body)
	hash := sha1.New()
	hash.Write(packet.Data)
	sha := hash.Sum(nil)

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientUpdateMachineAuthResponse, &protobuf.CMsgClientUpdateMachineAuthResponse{
		ShaFile: sha,
	})
	msg.SetTargetJobId(packet.SourceJobId)
	a.client.Send(msg)

	return &MachineAuthUpdateEvent{sha}
}

func (a *Auth) HandleAccountInfo(packet *protocol.Packet) *AccountInfoEvent {
	body := new(protobuf.CMsgClientAccountInfo)
	packet.ReadProtoMsg(body)
	return &AccountInfoEvent{
		PersonaName:          body.GetPersonaName(),
		Country:              body.GetIpCountry(),
		CountAuthedComputers: body.GetCountAuthedComputers(),
		AccountFlags:         steamlang.EAccountFlags(body.GetAccountFlags()),
		FacebookId:           body.GetFacebookId(),
		FacebookName:         body.GetFacebookName(),
	}
}
