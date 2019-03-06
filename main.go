package main

import (
	. "github.com/MediConCenHK/go-chaincode-common"
	. "github.com/davidkhala/fabric-common-chaincode-golang"
	"github.com/davidkhala/fabric-common-chaincode-golang/cid"
	. "github.com/davidkhala/goutils"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	"strings"
)

const (
	name             = "BC"
	signID           = "BC"
	retentionTime    = 2 * 86400 * 1000 //2 days
	randomBytes      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	collectionMember = "member"
	keySignKey       = "SignKey"     // private key to sign token
	keyAppUserCert   = "AppUserCert" // cert of app user allowed to invoke BC chaincode
	tokenIssuer      = "BC"
)

type BCChaincode struct {
	InsuranceChaincode
	Payer
}

func (t BCChaincode) verifyCreatorIdentity(expectedCert []byte) {
	creatorCert := cid.NewClientIdentity(t.CCAPI).CertificatePem

	if strings.Compare(string(creatorCert), string(expectedCert)) != 0 {
		t.Logger.Error("creator", string(creatorCert))
		t.Logger.Error("expectedCert", string(expectedCert))
		PanicString("tx creator's identity is not as expected")
		//M-BM0014
	}

}

func (t BCChaincode) GenTokens(auth MemberAuth, params []string) []byte {

	var memberID = params[0]

	var data memberData
	exist := t.GetPrivateObj(collectionMember, memberID, &data)

	var changed = false
	var tokenVerifyExpiryTime TimeLong
	var tokenPayExpiryTime TimeLong
	if exist {
		dataBefore := data
		data.TokenVerify, tokenVerifyExpiryTime = t.updateTokenByCase(memberID, TokenTypeVerify, data.TokenVerify)
		data.TokenPay, tokenPayExpiryTime = t.updateTokenByCase(memberID, TokenTypePay, data.TokenPay)
		changed = (data.TokenVerify != dataBefore.TokenVerify) || (data.TokenPay != dataBefore.TokenPay)
	} else {
		data = memberData{}
		data.TokenVerify, tokenVerifyExpiryTime = t.createAndSaveToken(memberID, TokenTypeVerify)
		data.TokenPay, tokenPayExpiryTime = t.createAndSaveToken(memberID, TokenTypePay)
		changed = true
	}

	if changed {
		t.Logger.Info("update token for member:", memberID, data)
		t.PutPrivateObj(collectionMember, memberID, data)
	}

	type responseData struct {
		memberData
		TokenVerifyExpiryTime TimeLong
		TokenPayExpiryTime    TimeLong
	}
	return ToJson(responseData{data, tokenVerifyExpiryTime, tokenPayExpiryTime})
}

func (t BCChaincode) GetMemberData(params []string) []byte {
	var memberID = params[0]
	var memberDataObj memberData
	exist := t.GetPrivateObj(collectionMember, memberID, &memberDataObj)
	if ! exist {
		PanicString("memberID not exist:" + memberID)
		//M-BC0003
	}
	return ToJson(memberDataObj)
}

func (t BCChaincode) Init(stub shim.ChaincodeStubInterface) (response peer.Response) {
	defer Deferred(DeferHandlerPeerResponse, &response)
	t.Prepare(stub)
	t.Logger.Info("Init")

	// AppUserCert is used to validate the tx creator's identity
	// when init, pass in the BC blockchain application's user certificate
	var transient = t.GetTransient()

	var appUserCertPem = transient[keyAppUserCert]
	if appUserCertPem != nil {
		t.PutState(keyAppUserCert, appUserCertPem)
	}

	return shim.Success(nil)
}
func (t BCChaincode) Invoke(stub shim.ChaincodeStubInterface) (response peer.Response) {
	defer Deferred(DeferHandlerPeerResponse, &response)
	t.Prepare(stub)
	var fcn, params = stub.GetFunctionAndParameters()
	t.Logger.Info("Invoke", fcn)
	var responseBytes []byte

	// validate creator's identity, only BC blockchain application's user is allowed
	t.verifyCreatorIdentity(t.GetState(keyAppUserCert))

	switch fcn {
	case Payer_fcn_genTokens:
		responseBytes = t.GenTokens(t.MemberAuth, params)
	case Payer_fcn_getMemberData:
		responseBytes = t.GetMemberData(params)
	default:
		PanicString("unknown fcn:" + fcn)
		//M-BC0007
	}
	return shim.Success(responseBytes)

}

func main() {
	var cc = BCChaincode{InsuranceChaincode: NewInsuranceChaincode(name)}
	ChaincodeStart(cc)
}
