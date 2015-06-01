package kademlia

// Contains the core kademlia type. In addition to core state, this type serves
// as a receiver for the RPC methods, which is required by that package.
//Git Test

import (
	"container/list"
	// "encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"sort"
	"strconv"
	// "strings"
	"sync"
	"time"
	// "os"
	// "bytes"
)

// const (
// 	ALPHA = 3
// 	b     = 8 * IDBytes
// 	k     = 20
// )
const (
	TOTAL_BUCKETS                 = 8 * IDBytes
	MAX_BUCKET_SIZE               = 20
	ALPHA                         = 3
	TIME_INTERVAL   time.Duration = 1500 * time.Millisecond
	RERPONSE_LIMIT  time.Duration = 1000 * time.Millisecond
)

// Kademlia type. You can put whatever state you need in this.
type Kademlia struct {
	NodeID      ID
	SelfContact Contact
	buckets     [IDBytes * 8]*list.List
	storeMutex  sync.RWMutex
	storeMap    map[ID][]byte
	vdoMap      map[ID]VanashingDataObject
}

type ContactDistance struct {
	SelfContact Contact
	Distance    ID
}

type ByDistance []ContactDistance

type Stopper struct {
	stopMutex sync.RWMutex
	value     int
	//0: No stop
	//1: Have accumulate k active
	//2: No improve in shortlist
	//3: Found value
}

type Counter struct {
	counterMutex sync.RWMutex
	value        int
}

type Valuer struct {
	value  []byte
	NodeID ID
}

type ReturnValuer struct {
	returnedValueMap    map[ID]bool
	value               []byte
	returnedValuerMutex sync.RWMutex
}

type UnqueriedList struct {
	list  []ContactDistance
	mutex sync.RWMutex
}

type ResultShortlist struct {
	list  []Contact
	mutex sync.RWMutex
}

//CHECK IF UNQUERIED LIST IS IMPROVED
type CheckImproved struct {
	value bool
	mutex sync.RWMutex
}

type QueryWaitList struct {
	waitList       []ContactDistance
	queryListMutex sync.RWMutex
}

type ShortestDistance struct {
	shortDistanceMutex sync.RWMutex
	Distance           ID
	selfContact        Contact
}

type Contacter struct {
	selfContact Contact
	contactList []Contact
}

//vanish
func (k *Kademlia) DoVanishData(vdoid ID, data []byte, N byte, threshold byte) string {
	vdo := VanishData(*k, data, N, threshold)
	if len(vdo.Ciphertext) == 0 {
		return "vdo is nil"
	}
	k.storeMutex.Lock()
	k.vdoMap[vdoid] = vdo
	k.storeMutex.Unlock()
	return "ok"
}

func NewKademlia(nodeid ID, laddr string) *Kademlia {
	// TODO: Initialize other state here as you add functionality.
	k := new(Kademlia)
	k.NodeID = nodeid
	for i := 0; i < len(k.buckets); i++ {
		k.buckets[i] = list.New()
	}

	// make message map
	k.storeMap = make(map[ID][]byte)
	k.vdoMap = make(map[ID]VanashingDataObject)

	s := rpc.NewServer() // Create a new RPC server
	s.Register(&KademliaCore{k})
	_, port, _ := net.SplitHostPort(laddr)                           // extract just the port number
	s.HandleHTTP(rpc.DefaultRPCPath+port, rpc.DefaultDebugPath+port) // I'm making a unique RPC path for this instance of Kademlia

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Fatal("Listen: ", err)
	}
	// Run RPC server forever.
	go http.Serve(l, nil)

	// Add self contact
	hostname, port, _ := net.SplitHostPort(l.Addr().String())
	port_int, _ := strconv.Atoi(port)
	ipAddrStrings, err := net.LookupHost(hostname)
	var host net.IP
	for i := 0; i < len(ipAddrStrings); i++ {
		host = net.ParseIP(ipAddrStrings[i])
		if host.To4() != nil {
			break
		}
	}
	// fmt.Println("new : " + host.String())
	k.SelfContact = Contact{k.NodeID, host, uint16(port_int)}
	return k
}

type NotFoundError struct {
	id  ID
	msg string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%x %s", e.id, e.msg)
}

func (k *Kademlia) FindContact(nodeId ID) (*Contact, error) {
	// Find contact with provided ID
	if nodeId == k.SelfContact.NodeID {
		return &k.SelfContact, nil
	}
	bucket := k.FindBucket(nodeId)
	if bucket == nil {
		return nil, &NotFoundError{nodeId, "Not found"}
	}
	res, err := k.FindContactInBucket(nodeId, bucket)
	if err == nil {
		c := res.Value.(Contact)
		return &c, nil
	}
	return nil, &NotFoundError{nodeId, "Not found"}
}

//DoUnVanishData
func (k *Kademlia) DoUnVanishData(contact *Contact, searchVodId ID) string {
	// If all goes well, return "OK: <output>", otherwise print "ERR: <messsage>"

	// client, err := rpc.DialHTTP("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)))
	client, err := rpc.DialHTTPPath("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)), rpc.DefaultRPCPath+strconv.Itoa(int(contact.Port)))

	if err != nil {

		return err.Error()
	}

	//create find node request and result
	getVDORequest := new(GetVDORequest)
	getVDORequest.Sender = k.SelfContact
	getVDORequest.MsgID = NewRandomID()
	getVDORequest.VdoID = searchVodId

	getVDOResult := new(GetVDOResult)

	//find node
	err = client.Call("KademliaCore.GetVDO", getVDORequest, getVDOResult)
	if err != nil {
		return err.Error()
	}

	vdoRes := getVDOResult.VDO

	data := UnvanishData(*k, vdoRes)

	if len(data) != 0 {
		result := string(data[:])

		return "ok, Unvanish result is: " + result
	} else {
		return "No Record"
	}
}

// This is the function to perform the RPC
func (k *Kademlia) DoPing(host net.IP, port uint16) string {

	var ping PingMessage
	ping.MsgID = NewRandomID()
	ping.Sender = k.SelfContact

	// fmt.Println("***IN DO ping: " + k.SelfContact.Host.String())

	var pong PongMessage
	// client, err := rpc.DialHTTP("tcp", string(host) + ":" + string(port))
	// client, err := rpc.DialHTTP("tcp", host.String()+":"+strconv.Itoa(int(port)))
	client, err := rpc.DialHTTPPath("tcp", host.String()+":"+strconv.Itoa(int(port)), rpc.DefaultRPCPath+strconv.Itoa(int(port)))

	if err != nil {
		log.Fatal("DialHTTP: ", err)
	}
	err = client.Call("KademliaCore.Ping", ping, &pong)

	if err != nil {
		return "ERR: " + err.Error()
	}

	defer client.Close()
	k.UpdateContact(pong.Sender)

	return "ok"
}

func (k *Kademlia) DoStore(contact *Contact, key ID, value []byte) string {
	//create store request and result
	storeRequest := new(StoreRequest)
	storeRequest.MsgID = NewRandomID()
	storeRequest.Sender = k.SelfContact
	storeRequest.Key = key
	storeRequest.Value = value

	storeResult := new(StoreResult)

	// store
	// rpc.DialHTTP("tcp", host.String() + ":" + strconv.Itoa(int(port)))
	// client, err := rpc.DialHTTP("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)))
	client, err := rpc.DialHTTPPath("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)), rpc.DefaultRPCPath+strconv.Itoa(int(contact.Port)))

	if err != nil {
		return err.Error()
	}

	err = client.Call("KademliaCore.Store", storeRequest, storeResult)

	//check error
	if err != nil {
		return err.Error()
	}
	//n := bytes.Index(value, []byte{0})
	fmt.Println("Store " + "key:" + key.AsString() + "Value: " + string(value[:len(value)-1]) + "len: " + strconv.Itoa(len(value)) + " to " + contact.NodeID.AsString() + " Successfully")
	k.UpdateContact(*contact)
	defer client.Close()
	return "ok"
}

func (k *Kademlia) DoFindNode(contact *Contact, searchKey ID) string {
	// If all goes well, return "OK: <output>", otherwise print "ERR: <messsage>"

	// client, err := rpc.DialHTTP("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)))
	client, err := rpc.DialHTTPPath("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)), rpc.DefaultRPCPath+strconv.Itoa(int(contact.Port)))

	if err != nil {

		return err.Error()
	}

	//create find node request and result
	findNodeRequest := new(FindNodeRequest)
	findNodeRequest.Sender = k.SelfContact
	findNodeRequest.MsgID = NewRandomID()
	findNodeRequest.NodeID = searchKey

	findNodeRes := new(FindNodeResult)

	//find node
	err = client.Call("KademliaCore.FindNode", findNodeRequest, findNodeRes)
	if err != nil {
		return err.Error()
	}

	//update contact
	var res string
	for _, contact := range findNodeRes.Nodes {
		k.UpdateContact(contact)
	}

	res = k.ContactsToString(findNodeRes.Nodes)
	if res == "" {
		return "No Record"
	}
	return "ok, result is: " + res
}

func (k *Kademlia) DoFindValue(contact *Contact, searchKey ID) string {
	// If all goes well, return "OK: <output>", otherwise print "ERR: <messsage>"
	// client, err := rpc.DialHTTP("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)))
	client, err := rpc.DialHTTPPath("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)), rpc.DefaultRPCPath+strconv.Itoa(int(contact.Port)))

	if err != nil {
		return err.Error()
	}

	//create find value request and result
	findValueReq := new(FindValueRequest)
	findValueReq.Sender = k.SelfContact
	findValueReq.MsgID = NewRandomID()
	findValueReq.Key = searchKey

	findValueRes := new(FindValueResult)

	//find value
	err = client.Call("KademliaCore.FindValue", findValueReq, findValueRes)

	if err != nil {
		return err.Error()
	}

	defer client.Close()

	//update contact
	k.UpdateContact(*contact)

	var res string
	//if value if found return value, else return closest contacts
	if findValueRes.Value != nil {
		res = res + string(findValueRes.Value[:])
	} else {
		res = res + k.ContactsToString(findValueRes.Nodes)
	}
	if res == "" {
		return "No Record"
	}
	return "ok, result is: " + res
}

func (k *Kademlia) LocalFindValue(searchKey ID) string {
	// TODO: Implement
	k.storeMutex.Lock()
	value, ok := k.storeMap[searchKey]
	k.storeMutex.Unlock()
	if ok {
		return "OK:" + string(value[:])
	} else {
		return "ERR: Not implemented"
	}
	// If all goes well, return "OK: <output>", otherwise print "ERR: <messsage>"
}

func (k *Kademlia) DoIterativeFindNode(id ID) string {

	shortlist := k.IterativeFindNode(id)
	// shortcontacts := FindClosestContactsBySort(shortlist)
	return k.ContactsToString(shortlist)
}

func (k *Kademlia) IterativeFindNode(id ID) []Contact {

	// store active nodes(queried)
	shortlist := make(chan Contact, MAX_BUCKET_SIZE)

	//node that we have seen
	seenMap := make(map[ID]bool)

	//nodes that have not been queried yet
	unqueriedList := new(UnqueriedList)
	unqueriedList.list = make([]ContactDistance, 0)

	//channel for query result
	res := make(chan []Contact, 120)

	//stopper for rpc request
	stopper := new(Stopper)

	//initialize shortlist, seenmap
	initializeContacts := k.FindClosestContacts(id, k.NodeID)
	if len(initializeContacts) > ALPHA {
		initializeContacts = initializeContacts[:3]
	}

	//result to return
	resultShortlist := new(ResultShortlist)

	//global closest
	closest := k.SelfContact.NodeID.Xor(id)

	//check if unqueried list is improved
	checkImproved := new(CheckImproved)
	checkImproved.value = true

	//stop channel for time
	stop := make(chan bool, 100)

	//initialize unqueriedlist and seenmap
	for i := 0; i < ALPHA && i < len(initializeContacts); i++ {
		contact := initializeContacts[i]
		seenMap[contact.NodeID] = true
		unqueriedList.list = append(unqueriedList.list, k.ContactToDistanceContact(contact, id))
	}

	// fmt.Println(".........find closet contact.........")
	// fmt.Println(k.ContactsToString(k.FindClosestContacts(id, k.NodeID)))

	// fmt.Println(".........find closet contact.........")
	// fmt.Println(k.ContactsToString(initializeContacts))

	//add res to shortlist
	go func() {
		for {
			select {
			case contacts := <-res:
				tempContacts := make([]ContactDistance, 0)
				for _, contact := range contacts {
					if _, ok := seenMap[contact.NodeID]; ok == false {
						tempContacts = append(tempContacts, k.ContactToDistanceContact(contact, id))
						seenMap[contact.NodeID] = true
					}
				}

				//append closest node and sort
				unqueriedList.mutex.Lock()
				unqueriedList.list = append(unqueriedList.list, tempContacts...)
				sort.Sort(ByDistance(unqueriedList.list))
				// fmt.Println("unqueried list")
				// fmt.Println(k.FindClosestContactsBySort(unqueriedList.list))
				unqueriedList.mutex.Unlock()

				//check if unqueried is improved,
				checkImproved.mutex.RLock()
				ifImproved := checkImproved.value
				checkImproved.mutex.RUnlock()

				if ifImproved == true {
					unqueriedList.mutex.RLock()
					unqueriedListLength := len(unqueriedList.list)
					var firstElement ContactDistance
					if unqueriedListLength > 0 {
						firstElement = unqueriedList.list[0]
					}
					unqueriedList.mutex.RUnlock()

					//check if improved
					if unqueriedListLength != 0 && firstElement.SelfContact.NodeID.Xor(id).Compare(closest) == 1 {
						checkImproved.mutex.Lock()
						checkImproved.value = false
						checkImproved.mutex.Unlock()
					} else if unqueriedListLength != 0 && firstElement.SelfContact.NodeID.Xor(id).Compare(closest) != 1 {
						closest = firstElement.SelfContact.NodeID.Xor(id)
					}

					if unqueriedListLength == 0 {
						if len(res) == 0 {
							stopper.stopMutex.Lock()
							stopper.value = 2
							stopper.stopMutex.Unlock()
							stop <- true
							break
						} else {
							continue
						}
					}
				}
			default:
			}
		}
	}()

	for {
		// check if unqueried list is empty and if there response in flight
		unqueriedList.mutex.RLock()
		tempLength := len(unqueriedList.list)
		unqueriedList.mutex.RUnlock()

		if tempLength == 0 {
			time.Sleep(TIME_INTERVAL)
			unqueriedList.mutex.RLock()
			tempLength = len(unqueriedList.list)
			unqueriedList.mutex.RUnlock()

			if len(res) == 0 && tempLength == 0 {
				stop <- true
				break
			}
		}

		// alpha query
		for i := 0; i < ALPHA; i++ {
			//check if unqueried list is empty
			unqueriedList.mutex.RLock()
			unqueriedListLength := len(unqueriedList.list)
			unqueriedList.mutex.RUnlock()
			if unqueriedListLength == 0 {
				break
			}

			unqueriedList.mutex.RLock()
			front := unqueriedList.list[0]
			unqueriedList.mutex.RUnlock()

			//check if end
			stopper.stopMutex.RLock()
			stopperValue := stopper.value
			stopper.stopMutex.RUnlock()

			if stopperValue != 0 {
				break
			}

			//get first contact from unqueriedList
			test := make([]Contact, 0)
			test = append(test, front.SelfContact)
			//remove this contact
			unqueriedList.mutex.Lock()
			unqueriedList.list = unqueriedList.list[1:]
			unqueriedList.mutex.Unlock()

			//type contact
			contact := front.SelfContact

			go func() {
				err, response := k.rpcQuery(contact, id, res)

				if err == nil {

					// add this active node to shortlist
					shortlist <- contact

					if len(shortlist) >= MAX_BUCKET_SIZE {
						stopper.stopMutex.Lock()
						stopper.value = 1
						stopper.stopMutex.Unlock()
						stop <- true
						return
					}

					//if is improved add the response to the res
					checkImproved.mutex.RLock()
					if checkImproved.value == true {
						res <- response
					}
					checkImproved.mutex.RUnlock()
				}
			}()
		}
		select {

		case <-time.After(TIME_INTERVAL):
		case <-stop:
			if len(shortlist) == MAX_BUCKET_SIZE || len(res) == 0 {
				resultShortlist.mutex.Lock()
				resultShortlist.list = make([]Contact, len(shortlist))
				channelLength := len(shortlist)
				for i := 0; i < channelLength; i++ {
					resultShortlist.list[i] = <-shortlist
				}
				resultShortlist.mutex.Unlock()
				return resultShortlist.list
			}
			break
		default:
		}
	}

	//make sure that res is flushed to the shortlist

	for {
		if len(shortlist) == MAX_BUCKET_SIZE || len(res) == 0 {
			break
		}
	}

	//return shortlist
	resultShortlist.mutex.Lock()
	resultShortlist.list = make([]Contact, len(shortlist))
	channelLength := len(shortlist)
	for i := 0; i < channelLength; i++ {
		resultShortlist.list[i] = <-shortlist
	}
	resultShortlist.mutex.Unlock()
	return resultShortlist.list
}

//rpc query for iterativefindnode
func (k *Kademlia) rpcQuery(node Contact, searchId ID, res chan []Contact) (error, []Contact) {
	client, err := rpc.DialHTTPPath("tcp", node.Host.String()+":"+strconv.Itoa(int(node.Port)), rpc.DefaultRPCPath+strconv.Itoa(int(node.Port)))
	// client, err := rpc.DialHTTP("tcp", node.Host.String()+":"+strconv.Itoa(int(node.Port)))

	if err != nil {
		return err, nil
	}

	//create find node request and result
	findNodeRequest := new(FindNodeRequest)
	findNodeRequest.Sender = k.SelfContact
	findNodeRequest.MsgID = NewRandomID()
	findNodeRequest.NodeID = searchId

	findNodeRes := new(FindNodeResult)

	//find node
	err = client.Call("KademliaCore.FindNode", findNodeRequest, findNodeRes)

	if err != nil {
		return err, nil
	}

	defer client.Close()

	//update contact
	k.UpdateContact(node)
	for _, contact := range findNodeRes.Nodes {
		k.UpdateContact(contact)
	}

	return err, findNodeRes.Nodes
}

func (k *Kademlia) DoIterativeStore(key ID, value []byte) string {
	// For project 2!
	contactList := k.IterativeFindNode(key)
	var result string
	for _, contact := range contactList {
		res := k.DoStore(&contact, key, value)
		if res == "ok" {
			result = result + "NodeId" + contact.NodeID.AsString()
		}
	}
	return result
}
func (k *Kademlia) DoIterativeFindValue(key ID) string {
	// fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Come in to Iterative Find Value~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	// For project 2!
	shortList := make(chan Contact, MAX_BUCKET_SIZE)

	//node that we have seen
	seenMap := make(map[ID]bool)
	//returnedValueMap := make(map[ID]bool)

	returnValuer := new(ReturnValuer)
	returnValuer.returnedValueMap = make(map[ID]bool)
	//nodes that have not been queried yet
	queryWaitList := new(QueryWaitList)
	queryWaitList.waitList = make([]ContactDistance, 0)

	//init the stopper
	stopper := new(Stopper)
	stopper.value = 0

	//init CloestNode
	clostestNode := new(ShortestDistance)
	for i := 0; i < IDBytes; i++ {
		clostestNode.Distance[i] = uint8(255)
	}
	var clostestNodeImproved bool
	clostestNodeImproved = true

	// contactChan := make(chan []Contact, MAX_BUCKET_SIZE*MAX_BUCKET_SIZE*2)
	contactChan := make(chan Contacter, MAX_BUCKET_SIZE*3)
	valueChan := make(chan Valuer, MAX_BUCKET_SIZE*3)
	stop := make(chan bool, MAX_BUCKET_SIZE)

	//initialize
	var returnValue []byte
	contacts := k.FindClosestContacts(key, k.NodeID)
	if len(contacts) > 3 {
		contacts = contacts[:ALPHA]
	}
	for _, contact := range contacts {
		seenMap[contact.NodeID] = true
		queryWaitList.queryListMutex.Lock()
		queryWaitList.waitList = append(queryWaitList.waitList, k.ContactToDistanceContact(contact, key))
		queryWaitList.queryListMutex.Unlock()

	}

	go func() {
		for {
			select {
			case contacter := <-contactChan:
				//fmt.Println("ShortList Active Incoming")
				contacts := contacter.contactList
				activeContact := contacter.selfContact
				shortList <- activeContact
				if len(shortList) == MAX_BUCKET_SIZE {
					stopper.stopMutex.Lock()
					stopper.value = 1
					stopper.stopMutex.Unlock()
					stop <- true
					return
				}
				if clostestNodeImproved && len(contacts) > 0 {
					for _, contact := range contacts {
						if _, ok := seenMap[contact.NodeID]; ok == false {
							queryWaitList.queryListMutex.Lock()
							//fmt.Println("Add into querywaitlist")
							queryWaitList.waitList = append(queryWaitList.waitList, k.ContactToDistanceContact(contact, key))
							queryWaitList.queryListMutex.Unlock()
							seenMap[contact.NodeID] = true
						}
					}
					//sort shortlist
					queryWaitList.queryListMutex.Lock()
					sort.Sort(ByDistance(queryWaitList.waitList))
					if len(queryWaitList.waitList) == 0 {
						//fmt.Println("not improve because wait list length is 0!!!!!!!!!!!!!")
						clostestNodeImproved = false
						queryWaitList.queryListMutex.Unlock()
						break
					}
					clostestTemp := queryWaitList.waitList[0]
					distanceTemp := clostestTemp.Distance
					queryWaitList.queryListMutex.Unlock()
					//check if short list is improved
					clostestNode.shortDistanceMutex.Lock()
					if clostestNode.Distance.Compare(clostestNode.Distance) == 1 {
						//fmt.Println("not improve because no close!!!!!!!!!!!!!!!!!!!!!!!")
						clostestNodeImproved = false
					} else {
						clostestNode.Distance = distanceTemp
						clostestNode.selfContact = clostestTemp.SelfContact
					}
					clostestNode.shortDistanceMutex.Unlock()
				}
			case valuer := <-valueChan:
				//fmt.Println("Value returned")
				//returnValue = valuer.value
				returnValuer.returnedValuerMutex.Lock()
				returnValuer.returnedValueMap[valuer.NodeID] = true
				returnValuer.value = valuer.value
				returnValuer.returnedValuerMutex.Unlock()
				//returnedValueMap[valuer.NodeID] = true
				stopper.stopMutex.Lock()
				stopper.value = 3
				stopper.stopMutex.Unlock()
				stop <- true
				return
			default:

			}
		}
	}()

	//stop channel for time
HandleLoop:
	for {
		//fmt.Println("Dead here 1")
		queryWaitList.queryListMutex.RLock()
		querylistLen := len(queryWaitList.waitList)
		queryWaitList.queryListMutex.RUnlock()
		//fmt.Println("Dead here 1.1")

		//Important here
		if len(contactChan) == 0 && len(valueChan) == 0 {
			time.Sleep(TIME_INTERVAL)
			if querylistLen == 0 {
				//fmt.Println("Dead here 2")
				stopper.stopMutex.Lock()
				stopper.value = 2
				stopper.stopMutex.Unlock()
				// fmt.Println("Set the stop")
				stop <- true
			}
		}
		queryWaitList.queryListMutex.Lock()
		sort.Sort(ByDistance(queryWaitList.waitList))
		queryWaitList.queryListMutex.Unlock()
		//fmt.Println("Dead here 1.2")

		for i := 0; i < ALPHA && querylistLen > 0; i++ {
			//check if end
			//fmt.Println("Dead here 3")

			stopper.stopMutex.RLock()
			if stopper.value != 0 {
				break
			}
			stopper.stopMutex.RUnlock()
			queryWaitList.queryListMutex.Lock()
			contact := queryWaitList.waitList[0].SelfContact
			queryWaitList.waitList = queryWaitList.waitList[1:]
			querylistLen = len(queryWaitList.waitList)
			queryWaitList.queryListMutex.Unlock()

			go func() {
				fmt.Println("Sent a RPC")
				k.iterFindValuQeuery(contact, key, contactChan, valueChan)
			}()
		}
		select {
		case <-time.After(TIME_INTERVAL):
			break
		case <-stop:
			// fmt.Println("Stop here Print")
			break HandleLoop
		}
	}
	//wait till zero
	//fmt.Println("Dead here 4")

	var stopType int
	stopper.stopMutex.RLock()
	stopType = stopper.value
	stopper.stopMutex.RUnlock()
	//fmt.Println("Dead here 5")

	for {
		//fmt.Println("Waiting for zero")
		if stopType != 3 && len(valueChan) != 0 {
			updatedValuer := <-valueChan
			//returnValue = updatedValuer.value
			returnValuer.returnedValuerMutex.Lock()
			returnValuer.value = updatedValuer.value
			returnValuer.returnedValueMap[updatedValuer.NodeID] = true
			returnValuer.returnedValuerMutex.Unlock()
			stopper.stopMutex.Lock()
			stopper.value = 3
			stopType = 3
			stopper.stopMutex.Unlock()
			//fmt.Println("OK ValueChan")
			break
		} else {
			break
		}
	}

	var returnString string
	// var returnContacts []Contact
	//fmt.Println("~~~~~~~~~~~~~~~~~Why stop" + strconv.Itoa(stopType))

	if stopType == 3 {
		//fmt.Println("Find Value stop 3!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		fmt.Println(strconv.Itoa(len(returnValuer.returnedValueMap)))
		returnValue = returnValuer.value
		// shortListLen := len(shortList)
		// for i := 0; i < shortListLen; i++ {
		// 	contactItem := <-shortList
		// 	returnContacts = append(returnContacts, contactItem)
		// }
		// for _, contactItem := range returnContacts {
		// 	if _, ok := returnedValueMap[contactItem.NodeID]; ok == false {
		// 		k.DoStore(&contactItem, key, returnValue)
		// 	}
		// }
		// // returnString = "Value: " + string(returnValue[:])
		// for k := range returnedValueMap {
		// 	returnString = returnString + "Value: " + string(returnValue[:]) + " ID: " + k.AsString() + ", "
		// }
		// returnString = returnString[:len(returnString)-2]
		clostestNode.shortDistanceMutex.RLock()
		dostoreContact := clostestNode.selfContact
		clostestNode.shortDistanceMutex.RUnlock()
		k.DoStore(&dostoreContact, key, returnValue)
		for k := range returnValuer.returnedValueMap {
			//fmt.Println("Here in Find value: " + string(returnValue[:]))
			returnString = returnString + " ID: " + k.AsString() + " Value: " + string(returnValue[:])
			break
		}
		//returnString = returnString[:len(returnString)-2]
	} else {
		returnString = "ERR: Value not found"
	}
	return returnString
}

func (k *Kademlia) iterFindValuQeuery(contact Contact, searchKey ID, contactChan chan Contacter, valuerChan chan Valuer) error {
	client, err := rpc.DialHTTPPath("tcp", contact.Host.String()+":"+strconv.Itoa(int(contact.Port)), rpc.DefaultRPCPath+strconv.Itoa(int(contact.Port)))
	if err != nil {
		return err
	}

	//create find value request and result
	findValueReq := new(FindValueRequest)
	findValueReq.Sender = k.SelfContact
	findValueReq.MsgID = NewRandomID()
	findValueReq.Key = searchKey

	findValueRes := new(FindValueResult)

	//find value
	err = client.Call("KademliaCore.FindValue", findValueReq, findValueRes)
	// fmt.Println("Get RPC call back")
	if err != nil {
		return err

	}

	defer client.Close()

	//update contact
	k.UpdateContact(contact)
	if findValueRes.Nodes != nil {
		for _, contactItem := range findValueRes.Nodes {
			k.UpdateContact(contactItem)
		}
	}
	if findValueRes.Value != nil {
		valuer := new(Valuer)
		valuer.value = findValueRes.Value
		valuer.NodeID = contact.NodeID
		// fmt.Println("Put things in valueChan")
		valuerChan <- *valuer
	} else if findValueRes.Nodes != nil {
		contacter := new(Contacter)
		contacter.contactList = findValueRes.Nodes
		contacter.selfContact = contact
		// fmt.Println("Put things in contactChan")
		contactChan <- *contacter
	}
	return err
}

///////////////////////////////////////////////////////////////////////////////
// methods for bucket
///////////////////////////////////////////////////////////////////////////////

func (k *Kademlia) UpdateContact(contact Contact) {
	//Find bucket
	// fmt.Println("Begin update")

	// fmt.Println("*********" + contact.Host.String())
	bucket := k.FindBucket(contact.NodeID)
	if bucket == nil {
		return
	}
	//Find contact, check if conact exist
	res, err := k.FindContactInBucket(contact.NodeID, bucket)

	//if contact has already existed, then move contact to the end of bucket
	if err == nil {
		k.storeMutex.Lock()
		bucket.MoveToBack(res)
		k.storeMutex.Unlock()
		//if contact is not found
	} else {
		//check if bucket is full, if not, add contact to the end of bucket
		k.storeMutex.RLock()
		bucketLength := bucket.Len()
		k.storeMutex.RUnlock()
		if bucketLength < MAX_BUCKET_SIZE {
			k.storeMutex.Lock()
			bucket.PushBack(contact)
			k.storeMutex.Unlock()

			//if bucket id full, ping the least recently contact node.
		} else {
			k.storeMutex.Lock()
			front := bucket.Front()
			k.storeMutex.Unlock()
			lrc_node := front.Value.(Contact)
			pingresult := k.DoPing(lrc_node.Host, lrc_node.Port)

			/*if least recent contact respond, ignore the new contact and move the least recent contact to
			  the end of the bucket
			*/
			if pingresult == "ok" {
				k.storeMutex.Lock()
				bucket.MoveToBack(front)
				k.storeMutex.Unlock()

				// if it does not respond, delete it and add the new contact to the end of the bucket
			} else {
				k.storeMutex.Lock()
				bucket.Remove(front)
				bucket.PushBack(contact)
				k.storeMutex.Unlock()

			}

		}

	}
	// fmt.Println("Update contact succeed, nodeid is : " + contact.NodeID.AsString())

}

func (k *Kademlia) FindBucket(nodeid ID) *list.List {
	k.storeMutex.RLock()
	defer k.storeMutex.RUnlock()
	prefixLength := k.NodeID.Xor(nodeid).PrefixLen()
	if prefixLength == 160 {
		return nil
	}
	bucketIndex := (IDBytes * 8) - prefixLength

	//if ping yourself, then the distance would be 160, and it will ran out of index
	if bucketIndex > (IDBytes*8 - 1) {
		bucketIndex = (IDBytes*8 - 1)
	}

	bucket := k.buckets[bucketIndex]
	return bucket
}

func (k *Kademlia) FindContactInBucket(nodeId ID, bucket *list.List) (*list.Element, error) {
	k.storeMutex.RLock()
	defer k.storeMutex.RUnlock()
	for i := bucket.Front(); i != nil; i = i.Next() {
		c := i.Value.(Contact)
		if c.NodeID.Equals(nodeId) {
			return i, nil
		}
	}
	return nil, &NotFoundError{nodeId, "Not found"}
}

func (k *Kademlia) FindClosestContacts(searchKey ID, senderKey ID) []Contact {
	contactDistanceList := k.FindAllKnownContact(searchKey, senderKey)
	result := k.FindClosestContactsBySort(contactDistanceList)
	return result

}

func (k *Kademlia) FindAllKnownContact(searchKey ID, senderKey ID) []ContactDistance {
	k.storeMutex.RLock()
	defer k.storeMutex.RUnlock()
	result := make([]ContactDistance, 0)
	bucketIndex := 0
	for bucketIndex < IDBytes*8 {
		targetBucket := k.buckets[bucketIndex]
		for i := targetBucket.Front(); i != nil; i = i.Next() {
			if !i.Value.(Contact).NodeID.Equals(senderKey) {
				contactD := new(ContactDistance)
				contactD.SelfContact = i.Value.(Contact)
				contactD.Distance = i.Value.(Contact).NodeID.Xor(searchKey)
				result = append(result, *contactD)
			}
		}
		bucketIndex++
	}

	if len(result) == 0 {
		return nil
	}

	return result

}

func (k *Kademlia) FindClosestContactsBySort(contactDistanceList []ContactDistance) []Contact {
	sort.Sort(ByDistance(contactDistanceList))
	result := make([]Contact, 0)
	for _, contactDistanceItem := range contactDistanceList {
		result = append(result, contactDistanceItem.SelfContact)
	}

	if len(result) == 0 {
		return nil
	}

	if len(result) <= MAX_BUCKET_SIZE {
		return result
	}

	result = result[0:MAX_BUCKET_SIZE]

	return result

}

func (a ByDistance) Len() int           { return len(a) }
func (a ByDistance) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByDistance) Less(i, j int) bool { return a[i].Distance.Less(a[j].Distance) }

//Convert contacts to string
func (k *Kademlia) ContactsToString(contacts []Contact) string {
	var res string
	for _, contact := range contacts {
		res = res + "{\"NodeID\": \"" + contact.NodeID.AsString() + "\", \"Host\": \"" + contact.Host.String() + "\", \"Port\": \"" + strconv.Itoa(int(contact.Port)) + "\"},"
	}
	if len(res) == 0 {
		return res
	}
	return res[:len(res)-1]
}

func (k *Kademlia) ContactDistanceToString(contacts []ContactDistance) string {
	var res string
	for _, contact := range contacts {
		res = res + "{\"NodeID\": \"" + contact.SelfContact.NodeID.AsString() + "\", \"Host\": \"" + contact.SelfContact.Host.String() + "\", \"Port\": \"" + strconv.Itoa(int(contact.SelfContact.Port)) + "\"},"
	}
	if len(res) == 0 {
		return res
	}
	return res[:len(res)-1]
}

func (k *Kademlia) PingWithOutUpdate(host net.IP, port uint16) string {

	var ping PingMessage
	ping.MsgID = NewRandomID()
	ping.Sender = k.SelfContact

	// fmt.Println("***IN DO ping: " + k.SelfContact.Host.String())

	var pong PongMessage
	// client, err := rpc.DialHTTP("tcp", string(host) + ":" + string(port))
	client, err := rpc.DialHTTP("tcp", host.String()+":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatal("DialHTTP: ", err)
	}
	err = client.Call("KademliaCore.Ping", ping, &pong)

	if err != nil {
		return "ERR: " + err.Error()
	}

	defer client.Close()
	return "ok"
}

func (k *Kademlia) compareDistance(c1 Contact, c2 Contact, id ID) int {
	distance1 := c1.NodeID.Xor(id)
	distance2 := c2.NodeID.Xor(id)
	return distance1.Compare(distance2)
}

/*================================================================================
Functions for Project 2
================================================================================ */

func (k *Kademlia) ContactToDistanceContact(contact Contact, id ID) ContactDistance {
	contactD := new(ContactDistance)
	contactD.SelfContact = contact
	contactD.Distance = contact.NodeID.Xor(id)
	return *contactD
}

func (k *Kademlia) DistanceContactToContact(distanceContact ContactDistance, id ID) Contact {
	contact := new(Contact)
	contact = &distanceContact.SelfContact
	return *contact
}
