package kademlia

// Contains definitions mirroring the Kademlia spec. You will need to stick
// strictly to these to be compatible with the reference implementation and
// other groups' code.

import (
	"errors"
	// "fmt"
	"net"
)

type KademliaCore struct {
	kademlia *Kademlia
}

// Host identification.
type Contact struct {
	NodeID ID
	Host   net.IP
	Port   uint16
}

///////////////////////////////////////////////////////////////////////////////
// Vanish
///////////////////////////////////////////////////////////////////////////////

type GetVDORequest struct {
	Sender Contact
	MsgID ID
	VdoID ID
}

type GetVDOResult struct {
	MsgID ID
	VDO VanashingDataObject
}

func (kc *KademliaCore) GetVDO (req GetVDORequest, RES *GetVDOResult) error {
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PING
///////////////////////////////////////////////////////////////////////////////
type PingMessage struct {
	Sender Contact
	MsgID  ID
}

type PongMessage struct {
	MsgID  ID
	Sender Contact
}

//USE kc call Ping method
func (kc *KademliaCore) Ping(ping PingMessage, pong *PongMessage) error {
	pong.MsgID = CopyID(ping.MsgID)

	// Specify the sender
	pong.Sender = kc.kademlia.SelfContact
	// fmt.Println("***IN  ping, sender: " + ping.Sender.Host.String())
	// fmt.Println("***IN  ping, self: " + pong.Sender.Host.String())

	// fmt.Println("Received ping!")
	// Update contact, etc
	kc.kademlia.UpdateContact(ping.Sender)

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// STORE
///////////////////////////////////////////////////////////////////////////////
type StoreRequest struct {
	Sender Contact
	MsgID  ID
	Key    ID
	Value  []byte
}

type StoreResult struct {
	MsgID ID
	Err   error
}

func (kc *KademliaCore) Store(req StoreRequest, res *StoreResult) error {
	// fmt.Println("Begin store!")
	k := (*kc).kademlia
	// store
	k.storeMutex.Lock()
	k.storeMap[req.Key] = req.Value
	// fmt.Println("store ")
	// fmt.Println(k.storeMap[req.Key])
	k.storeMutex.Unlock()

	//update contact
	k.UpdateContact(req.Sender)
	res.Err = nil
	// fmt.Println("Finish store " + string(req.Value) + "on " + k.NodeID.AsString())
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// FIND_NODE
///////////////////////////////////////////////////////////////////////////////
type FindNodeRequest struct {
	Sender Contact
	MsgID  ID
	NodeID ID
}

type FindNodeResult struct {
	MsgID ID
	Nodes []Contact
	Err   error
}

func (kc *KademliaCore) FindNode(req FindNodeRequest, res *FindNodeResult) error {

	k := (*kc).kademlia
	res.Nodes = k.FindClosestContacts(req.NodeID, req.Sender.NodeID)
	res.MsgID = req.MsgID

	//update contact
	k.UpdateContact(req.Sender)
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// FIND_VALUE
///////////////////////////////////////////////////////////////////////////////
type FindValueRequest struct {
	Sender Contact
	MsgID  ID
	Key    ID
}

// If Value is nil, it should be ignored, and Nodes means the same as in a
// FindNodeResult.
type FindValueResult struct {
	MsgID ID
	Value []byte
	Nodes []Contact
	Err   error
}

func (kc *KademliaCore) FindValue(req FindValueRequest, res *FindValueResult) error {
	k := (*kc).kademlia

	// test if key exists in map, if exists, ok = true
	k.storeMutex.RLock()
	value, ok := k.storeMap[req.Key]
	k.storeMutex.RUnlock()

	//if key exists
	if ok {
		res.MsgID = req.MsgID
		res.Value = value
		res.Nodes = nil
		res.Err = nil

		//if not found,  Otherwise the RPC is equivalent to a FIND_NODE and a set of k triples is returned.
	} else {

		//create find node request and result
		findNodeRequest := new(FindNodeRequest)
		findNodeRequest.Sender = req.Sender
		findNodeRequest.MsgID = NewRandomID()
		findNodeRequest.NodeID = req.Key

		findNodeRes := new(FindNodeResult)

		//find node
		err := kc.FindNode(*findNodeRequest, findNodeRes)
		if err != nil {
			res.Err = errors.New("Find Node Error")
		}

		res.MsgID = req.MsgID
		res.Value = nil
		res.Nodes = findNodeRes.Nodes
		res.Err = nil

	}

	//update contact
	k.UpdateContact(req.Sender)

	return nil
}
