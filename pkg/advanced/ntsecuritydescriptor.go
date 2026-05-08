package advanced

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapSDFlagsOID = "1.2.840.113556.1.4.801"

	aceTypeAccessAllowed       = 0x00
	aceTypeAccessAllowedObject = 0x05

	accessMaskGenericWrite       = 0x40000000
	accessMaskWriteDACL          = 0x00040000
	accessMaskWriteOwner         = 0x00080000
	accessMaskWriteProperty      = 0x00000020
	accessMaskControlAccess      = 0x00000100
	accessMaskGenericAll         = 0x10000000
	domainDNSClassSchemaIDGUID   = "19195a5a-6da0-11d0-afd3-00c04fd930c9"
	guidDSReplicationGetChanges  = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidDSReplicationGetChangesA = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidDSReplicationGetChangesF = "89e95b76-444d-4c62-991a-0facbeda640c"
)

type ACLControlEdge struct {
	TrusteeSID string   `json:"trustee_sid"`
	TrusteeDN  string   `json:"trustee_dn,omitempty"`
	TargetDN   string   `json:"target_dn"`
	Right      string   `json:"right"`
	Evidence   []string `json:"evidence,omitempty"`
}

func (aa *AdvancedAnalyzer) EnumerateNTSecurityDescriptorEdges() ([]ACLControlEdge, error) {
	if aa.Client == nil || aa.Client.GetConnection() == nil {
		return nil, fmt.Errorf("LDAP client not initialized")
	}

	control := ldap.NewControlString(ldapSDFlagsOID, true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}))
	req := ldap.NewSearchRequest(
		aa.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(|(adminCount=1)(objectClass=domainDNS))",
		[]string{"distinguishedName", "nTSecurityDescriptor"},
		[]ldap.Control{control},
	)
	resp, err := aa.Client.GetConnection().Search(req)
	if err != nil {
		return nil, fmt.Errorf("nTSecurityDescriptor search failed: %w", err)
	}

	sidToDN := aa.buildSIDToDNIndex()
	var out []ACLControlEdge
	for _, entry := range resp.Entries {
		targetDN := entry.GetAttributeValue("distinguishedName")
		raw := entry.GetRawAttributeValue("nTSecurityDescriptor")
		if len(raw) == 0 {
			continue
		}
		aces, err := parseDACL(raw)
		if err != nil {
			continue
		}
		for _, ace := range aces {
			rights := rightsFromACE(ace, strings.EqualFold(targetDN, aa.Client.GetBaseDN()))
			for _, right := range rights {
				edge := ACLControlEdge{
					TrusteeSID: ace.SID,
					TrusteeDN:  sidToDN[ace.SID],
					TargetDN:   targetDN,
					Right:      right,
					Evidence:   []string{fmt.Sprintf("ACE type=0x%02x mask=0x%08x", ace.AceType, ace.Mask)},
				}
				out = append(out, edge)
			}
		}
	}
	return out, nil
}

func (aa *AdvancedAnalyzer) buildSIDToDNIndex() map[string]string {
	index := make(map[string]string)
	entries, err := aa.Client.SearchSubtreePaged("(objectSid=*)", []string{"distinguishedName", "objectSid"}, 500)
	if err != nil {
		return index
	}
	for _, e := range entries {
		rawSID := e.GetRawAttributeValue("objectSid")
		sid, err := parseSID(rawSID)
		if err != nil {
			continue
		}
		index[sid] = e.DN
	}
	return index
}

type parsedACE struct {
	AceType         byte
	Mask            uint32
	Flags           uint32
	ObjectTypeGUID  string
	InheritedGUID   string
	SID             string
}

func parseDACL(sd []byte) ([]parsedACE, error) {
	if len(sd) < 20 {
		return nil, fmt.Errorf("descriptor too short")
	}
	if sd[0] != 1 {
		return nil, fmt.Errorf("unexpected descriptor revision %d", sd[0])
	}
	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 || daclOffset+8 > len(sd) {
		return nil, nil
	}
	dacl := sd[daclOffset:]
	if len(dacl) < 8 {
		return nil, fmt.Errorf("invalid dacl header")
	}
	aceCount := int(binary.LittleEndian.Uint16(dacl[4:6]))
	pos := 8
	out := make([]parsedACE, 0, aceCount)
	for i := 0; i < aceCount; i++ {
		if pos+4 > len(dacl) {
			break
		}
		aceType := dacl[pos]
		aceSize := int(binary.LittleEndian.Uint16(dacl[pos+2 : pos+4]))
		if aceSize < 8 || pos+aceSize > len(dacl) {
			break
		}
		aceData := dacl[pos : pos+aceSize]
		if aceType == aceTypeAccessAllowed {
			mask := binary.LittleEndian.Uint32(aceData[4:8])
			sid, err := parseSID(aceData[8:])
			if err == nil {
				out = append(out, parsedACE{AceType: aceType, Mask: mask, SID: sid})
			}
		}
		if aceType == aceTypeAccessAllowedObject && len(aceData) >= 16 {
			mask := binary.LittleEndian.Uint32(aceData[4:8])
			flags := binary.LittleEndian.Uint32(aceData[8:12])
			cur := 12
			var objGUID, inhGUID string
			if flags&0x1 != 0 && cur+16 <= len(aceData) {
				objGUID = parseGUIDLE(aceData[cur : cur+16])
				cur += 16
			}
			if flags&0x2 != 0 && cur+16 <= len(aceData) {
				inhGUID = parseGUIDLE(aceData[cur : cur+16])
				cur += 16
			}
			if cur < len(aceData) {
				sid, err := parseSID(aceData[cur:])
				if err == nil {
					out = append(out, parsedACE{
						AceType:        aceType,
						Mask:           mask,
						Flags:          flags,
						ObjectTypeGUID: objGUID,
						InheritedGUID:  inhGUID,
						SID:            sid,
					})
				}
			}
		}
		pos += aceSize
	}
	return out, nil
}

func rightsFromACE(ace parsedACE, isDomainObject bool) []string {
	var out []string
	if ace.Mask&accessMaskGenericAll != 0 {
		out = append(out, "GenericAll")
	}
	if ace.Mask&accessMaskGenericWrite != 0 || ace.Mask&accessMaskWriteProperty != 0 {
		out = append(out, "GenericWrite")
	}
	if ace.Mask&accessMaskWriteDACL != 0 {
		out = append(out, "WriteDacl")
	}
	if ace.Mask&accessMaskWriteOwner != 0 {
		out = append(out, "WriteOwner")
	}
	if ace.Mask&accessMaskControlAccess != 0 {
		if ace.ObjectTypeGUID == guidDSReplicationGetChanges ||
			ace.ObjectTypeGUID == guidDSReplicationGetChangesA ||
			ace.ObjectTypeGUID == guidDSReplicationGetChangesF {
			out = append(out, "DCSync")
		} else if ace.ObjectTypeGUID == "" && isDomainObject {
			out = append(out, "AllExtendedRights")
		}
	}
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func parseSID(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("sid too short")
	}
	rev := b[0]
	subCount := int(b[1])
	if len(b) < 8+subCount*4 {
		return "", fmt.Errorf("sid truncated")
	}
	authority := uint64(0)
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}
	parts := []string{fmt.Sprintf("S-%d-%d", rev, authority)}
	offset := 8
	for i := 0; i < subCount; i++ {
		sub := binary.LittleEndian.Uint32(b[offset : offset+4])
		parts = append(parts, fmt.Sprintf("%d", sub))
		offset += 4
	}
	return strings.Join(parts, "-"), nil
}

func parseGUIDLE(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	// little-endian parts per AD encoding
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	d4 := hex.EncodeToString(b[8:10])
	d5 := hex.EncodeToString(b[10:16])
	return fmt.Sprintf("%08x-%04x-%04x-%s-%s", d1, d2, d3, d4, d5)
}

