package signing

import "github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"

const (
	manifestPayloadName = "manifest.payload.json"
	signingRequestName  = "signing-request.json"
	maxPayloadBytes     = catalogv1.MaxSourceBytes
	maxRequestBytes     = 1 << 20
)

// SigningRequest is the signer-owned view of the candidate request. The alias
// keeps the bytes frozen by the independent Catalog V1 package.
type SigningRequest = catalogv1.SigningRequest

type Inspection struct {
	SourceID      string `json:"sourceId"`
	Version       uint64 `json:"version"`
	RequestDigest string `json:"requestDigest"`
	PayloadSHA256 string `json:"payloadSha256"`
	ObjectCount   int    `json:"objectCount"`
}

type PreparedCandidate struct {
	inspection Inspection
	payload    []byte
}

func (candidate *PreparedCandidate) Inspection() Inspection {
	if candidate == nil {
		return Inspection{}
	}
	return candidate.inspection
}
