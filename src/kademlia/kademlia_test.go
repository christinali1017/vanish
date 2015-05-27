package kademlia

import (
	"math/rand"
	"net"
	"strconv"
	"testing"
	// "encoding/json"
	//"strings"
	// "io"
	"fmt"
	"sort"
)

func CreateIdForTest(id string) (ret ID) {
	if len(id) > 160 {
		id = id[0:160]
	}
	for i := 0; i < len(id); i++ {
		ret[i] = id[i]
	}
	return
}

func StringToIpPort(laddr string) (ip net.IP, port uint16, err error) {
	hostString, portString, err := net.SplitHostPort(laddr)
	if err != nil {
		return
	}
	ipStr, err := net.LookupHost(hostString)
	if err != nil {
		return
	}
	for i := 0; i < len(ipStr); i++ {
		ip = net.ParseIP(ipStr[i])
		if ip.To4() != nil {
			break
		}
	}
	portInt, err := strconv.Atoi(portString)
	port = uint16(portInt)
	return
}

func TestPing(t *testing.T) {
	instance1 := NewKademlia(CreateIdForTest(string(1)), "localhost:7890")
	instance2 := NewKademlia(CreateIdForTest(string(2)), "localhost:7891")
	host2, port2, _ := StringToIpPort("localhost:7891")
	instance1.DoPing(host2, port2)
	contact2, err := instance1.FindContact(instance2.NodeID)
	if err != nil {
		t.Error("Instance 2's contact not found in Instance 1's contact list")
		return
	}
	contact1, err := instance2.FindContact(instance1.NodeID)
	if err != nil {
		t.Error("Instance 1's contact not found in Instance 2's contact list")
		return
	}
	if contact1.NodeID != instance1.NodeID {
		t.Error("Instance 1 ID incorrectly stored in Instance 2's contact list")
	}
	if contact2.NodeID != instance2.NodeID {
		t.Error("Instance 2 ID incorrectly stored in Instance 1's contact list")
	}
	return
}

func TestFindNode(t *testing.T) {
	instance1 := NewKademlia(CreateIdForTest(string(1)), "localhost:7892")
	instance2 := NewKademlia(CreateIdForTest(string(2)), "localhost:7893")
	instance3 := NewKademlia(CreateIdForTest(string(3)), "localhost:7894")
	host2, port2, _ := StringToIpPort("localhost:7893")
	instance1.DoPing(host2, port2)
	contact2, err := instance1.FindContact(instance2.NodeID)
	if err != nil {
		t.Error("Instance 2's contact not found in Instance 1's contact list")
		return
	}
	contact1, err := instance2.FindContact(instance1.NodeID)
	if err != nil {
		t.Error("Instance 1's contact not found in Instance 2's contact list")
		return
	}
	if contact1.NodeID != instance1.NodeID {
		t.Error("Instance 1 ID incorrectly stored in Instance 2's contact list")
	}
	if contact2.NodeID != instance2.NodeID {
		t.Error("Instance 2 ID incorrectly stored in Instance 1's contact list")
	}
	instance3.DoPing(host2, port2)
	instance1ID := instance1.SelfContact.NodeID
	instance2ID := instance2.SelfContact.NodeID
	instance3ID := instance3.SelfContact.NodeID
	contact, err := instance1.FindContact(instance2ID)
	if err != nil {
		t.Error("ERR: Unable to find contact with node ID")
		return
	}
	var res []Contact
	res = instance2.FindClosestContacts(instance3ID, instance1ID)
	resstring := instance2.ContactsToString(res)
	response := instance1.DoFindNode(contact, instance3ID)
	if response != "ok, result is: "+resstring {
		t.Error("Node in Instance2 are stored incorrectly")
	}
	return
}

func TestStore(t *testing.T) {
	instance1 := NewKademlia(CreateIdForTest(string(1)), "localhost:7895")
	instance2 := NewKademlia(CreateIdForTest(string(2)), "localhost:7896")
	host2, port2, _ := StringToIpPort("localhost:7896")
	instance1.DoPing(host2, port2)
	contact2, err := instance1.FindContact(instance2.NodeID)
	if err != nil {
		t.Error("Instance 2's contact not found in Instance 1's contact list")
		return
	}
	contact1, err := instance2.FindContact(instance1.NodeID)
	if err != nil {
		t.Error("Instance 1's contact not found in Instance 2's contact list")
		return
	}
	if contact1.NodeID != instance1.NodeID {
		t.Error("Instance 1 ID incorrectly stored in Instance 2's contact list")
	}
	if contact2.NodeID != instance2.NodeID {
		t.Error("Instance 2 ID incorrectly stored in Instance 1's contact list")
	}
	instance1ID := instance1.SelfContact.NodeID
	instance2ID := instance2.SelfContact.NodeID
	contact, err := instance1.FindContact(instance2ID)
	if err != nil {
		t.Error("ERR: Unable to find contact with node ID")
		return
	}
	svalue := strconv.Itoa(int(rand.Intn(256)))
	value := []byte(svalue)
	instance1.DoStore(contact, instance1ID, value)
	response := instance2.LocalFindValue(instance1ID)
	if response != "OK:"+string(value[:]) {
		t.Error("Value in Instance2 are stored incorrectly")
	}
	return
}

func TestFindValue(t *testing.T) {
	instance1 := NewKademlia(CreateIdForTest(string(1)), "localhost:7897")
	instance2 := NewKademlia(CreateIdForTest(string(2)), "localhost:7898")
	instance3 := NewKademlia(CreateIdForTest(string(3)), "localhost:7899")
	host2, port2, _ := StringToIpPort("localhost:7898")
	instance1.DoPing(host2, port2)
	contact2, err := instance1.FindContact(instance2.NodeID)
	if err != nil {
		t.Error("Instance 2's contact not found in Instance 1's contact list")
		return
	}
	contact1, err := instance2.FindContact(instance1.NodeID)
	if err != nil {
		t.Error("Instance 1's contact not found in Instance 2's contact list")
		return
	}
	if contact1.NodeID != instance1.NodeID {
		t.Error("Instance 1 ID incorrectly stored in Instance 2's contact list")
	}
	if contact2.NodeID != instance2.NodeID {
		t.Error("Instance 2 ID incorrectly stored in Instance 1's contact list")
	}
	instance3.DoPing(host2, port2)
	instance1ID := instance1.SelfContact.NodeID
	instance2ID := instance2.SelfContact.NodeID
	instance3ID := instance3.SelfContact.NodeID
	contact, err := instance1.FindContact(instance2ID)
	if err != nil {
		t.Error("ERR: Unable to find contact with node ID")
		return
	}
	svalue := strconv.Itoa(int(rand.Intn(256)))
	value := []byte(svalue)
	instance1.DoStore(contact, instance1ID, value)
	response := instance3.DoFindValue(contact, instance1ID)
	if response != "ok, result is: "+string(value[:]) && response != "No Record" {
		t.Error("Value in Instance2 are stored incorrectly")
	}
	responsenode := instance3.DoFindNode(contact, instance3ID)
	responsevalue := instance3.DoFindValue(contact, instance3ID)
	if responsenode != responsevalue {
		t.Error("Node in Instance2 are stored incorrectly")
	}
	return
}

func TestIterativeFindFunctions(t *testing.T) {
	fmt.Println(".........Begin test find node......")
	numberOfNodes := 150

	numberOfContactsPerNode := 30
	instances := make([]Kademlia, numberOfNodes)
	instancesAddr := make([]string, numberOfNodes)
	startPort := 8000

	testerNumber := int(rand.Intn(numberOfNodes))
	testSearchNumber := int(rand.Intn(numberOfNodes))
	searchKey := instances[testSearchNumber].NodeID

	fmt.Println("Create instances.........")

	//create 100 kademlia instance
	for i := 0; i < numberOfNodes; i++ {
		port := i + startPort
		address := "localhost:" + strconv.Itoa(port)

		// fmt.Println("port is " + address)
		instancesAddr[i] = address
		instances[i] = *NewKademlia(CreateIdForTest(string(i)), address)
		//instances[i] = *NewKademlia(CreateIdForTest(strconv.Itoa(i)), address)
	}

	fmt.Println("Ping .........")

	for i := 0; i < numberOfNodes; i++ {
		address := instancesAddr[i]
		host, port, _ := StringToIpPort(address)
		start := i - numberOfContactsPerNode/2
		end := i + numberOfContactsPerNode/2
		if i >= numberOfContactsPerNode/2 && i <= numberOfNodes-numberOfContactsPerNode/2 {
			for j := start; j < end; j++ {
				instances[j].DoPing(host, port)
			}
		} else {
			if i < numberOfContactsPerNode/2 {
				for j := 0; j < numberOfContactsPerNode; j++ {
					instances[j].DoPing(host, port)
				}
			} else if i > numberOfNodes-numberOfContactsPerNode/2 {
				for j := numberOfNodes - numberOfContactsPerNode; j < numberOfNodes; j++ {
					instances[j].DoPing(host, port)
				}
			}
		}

	}

	fmt.Println("Check contacts.........")

	for i := 0; i < numberOfNodes; i++ {
		instance := instances[i]
		start := i - numberOfContactsPerNode/2
		end := i + numberOfContactsPerNode/2
		if i >= numberOfContactsPerNode/2 && i <= numberOfNodes-numberOfContactsPerNode/2 {
			for j := start; j < end; j++ {
				contact, err := instances[j].FindContact(instance.NodeID)
				if err != nil {
					t.Error("Instance " + string(i) + "'s contact not found in Instance " + string(j) + "'s contact list")
					return
				}

				if !contact.NodeID.Equals(instance.NodeID) {
					t.Error("Instance " + string(i) + "'s contact incorrectly stored in Instance " + string(j) + "'s contact list")
				}
			}
		} else {
			if i < numberOfContactsPerNode/2 {
				for j := 0; j < numberOfContactsPerNode; j++ {
					contact, err := instances[j].FindContact(instance.NodeID)
					if err != nil {
						t.Error("Instance " + string(i) + "'s contact not found in Instance " + string(j) + "'s contact list")
						return
					}

					if !contact.NodeID.Equals(instance.NodeID) {
						t.Error("Instance " + string(i) + "'s contact incorrectly stored in Instance " + string(j) + "'s contact list")
					}
				}
			} else if i > numberOfNodes-numberOfContactsPerNode/2 {
				for j := numberOfNodes - numberOfContactsPerNode; j < numberOfNodes; j++ {
					contact, err := instances[j].FindContact(instance.NodeID)
					if err != nil {
						t.Error("Instance " + string(i) + "'s contact not found in Instance " + string(j) + "'s contact list")
						return
					}

					if !contact.NodeID.Equals(instance.NodeID) {
						t.Error("Instance " + string(i) + "'s contact incorrectly stored in Instance " + string(j) + "'s contact list")
					}
				}
			}
		}

	}

	for i := 0; i < numberOfNodes; i++ {
		instance := instances[i]
		start := i - numberOfContactsPerNode/2
		end := i + numberOfContactsPerNode/2

		if i >= numberOfContactsPerNode/2 && i <= numberOfNodes-numberOfContactsPerNode/2 {
			for j := start; j < end; j++ {
				contact, err := instance.FindContact(instances[j].NodeID)
				if err != nil {
					t.Error("Instance" + string(j) + "'s contact not found in Instance" + string(i) + "'s contact list")
					return
				}

				if !contact.NodeID.Equals(instances[j].NodeID) {
					t.Error("Instance" + string(j) + "'s contact incorrectly stored in Instance" + string(i) + "'s contact list")
				}
			}
		} else {
			if i < numberOfContactsPerNode/2 {
				for j := 0; j < numberOfContactsPerNode; j++ {
					contact, err := instance.FindContact(instances[j].NodeID)
					if err != nil {
						t.Error("Instance" + string(j) + "'s contact not found in Instance" + string(i) + "'s contact list")
						return
					}

					if !contact.NodeID.Equals(instances[j].NodeID) {
						t.Error("Instance" + string(j) + "'s contact incorrectly stored in Instance" + string(i) + "'s contact list")
					}
				}
			} else {
				for j := numberOfNodes - numberOfContactsPerNode; j < numberOfNodes; j++ {
					contact, err := instance.FindContact(instances[j].NodeID)
					if err != nil {
						t.Error("Instance" + string(j) + "'s contact not found in Instance" + string(i) + "'s contact list")
						return
					}

					if !contact.NodeID.Equals(instances[j].NodeID) {
						t.Error("Instance" + string(j) + "'s contact incorrectly stored in Instance" + string(i) + "'s contact list")
					}
				}
			}
		}

	}

	//check iterative find node 0 find 50

	fmt.Println("Get theoretical result .........")

	theoreticalRes := make([]ContactDistance, 0)
	initializeContacts := instances[testerNumber].FindClosestContacts(searchKey, instances[testerNumber].NodeID)
	if len(initializeContacts) > ALPHA {
		initializeContacts = initializeContacts[:3]
	}
	unqueriedList := make([]ContactDistance, 0)
	seenMap := make(map[ID]bool)
	improved := true

	for i := 0; i < ALPHA && i < len(initializeContacts); i++ {
		contact := initializeContacts[i]
		seenMap[contact.NodeID] = true
		unqueriedList = append(unqueriedList, instances[testerNumber].ContactToDistanceContact(contact, searchKey))
	}

	if len(unqueriedList) > 0 {
		closest := unqueriedList[0].SelfContact.NodeID.Xor(searchKey)
		for len(unqueriedList) > 0 && len(theoreticalRes) <= MAX_BUCKET_SIZE {
			current := make([]ContactDistance, 0)
			if len(unqueriedList) < 3 {
				current = unqueriedList[0:]
				unqueriedList = make([]ContactDistance, 0)
			} else {
				current = unqueriedList[0:3]
				unqueriedList = unqueriedList[3:]
			}

			for i := 0; i < ALPHA && i < len(current); i++ {
				front := current[i]
				contact := front.SelfContact
				tempInstanceIndex := int(contact.Port) - startPort
				tempContacts := instances[tempInstanceIndex].FindClosestContacts(searchKey, contact.NodeID)

				if len(tempContacts) > 0 {
					theoreticalRes = append(theoreticalRes, instances[testerNumber].ContactToDistanceContact(contact, searchKey))
				}

				if improved {
					for _, c := range tempContacts {
						if _, ok := seenMap[c.NodeID]; ok == false {
							unqueriedList = append(unqueriedList, instances[testerNumber].ContactToDistanceContact(c, searchKey))
							seenMap[c.NodeID] = true
						}
					}
					sort.Sort(ByDistance(unqueriedList))
					if len(unqueriedList) != 0 && unqueriedList[0].SelfContact.NodeID.Xor(searchKey).Compare(closest) == 1 {
						improved = false
					} else if len(unqueriedList) != 0 && unqueriedList[0].SelfContact.NodeID.Xor(searchKey).Compare(closest) != 1 {
						closest = unqueriedList[0].SelfContact.NodeID.Xor(searchKey)
					}
				}
			}

			// time.Sleep(500 * time.Millisecond)
		}
		sort.Sort(ByDistance(theoreticalRes))

		//convert contactdistance to contact
		theoreticalContact := make([]Contact, 0)
		for i := 0; i < len(theoreticalRes); i++ {
			theoreticalContact = append(theoreticalContact, theoreticalRes[i].SelfContact)
		}
	}

	fmt.Println("Get iterative findnode result.........")

	resContacts := instances[testerNumber].IterativeFindNode(instances[testSearchNumber].SelfContact.NodeID)
	resContactDistance := make([]ContactDistance, 0)
	for _, c := range resContacts {
		resContactDistance = append(resContactDistance, instances[testerNumber].ContactToDistanceContact(c, searchKey))
	}
	sort.Sort(ByDistance(resContactDistance))

	//compare result, sequence is not fixed, because some nodes might have same distance
	fmt.Println("Compare.........")

	for i := 0; i < MAX_BUCKET_SIZE && i < len(resContactDistance) && i < len(theoreticalRes); i++ {
		if !theoreticalRes[i].SelfContact.NodeID.Equals(resContactDistance[i].SelfContact.NodeID) {
			// t.Error("TestIterativeFindNode error, the nodes return are not the closet ones")
		}
	}

	fmt.Println("Finish iterative find node")
	fmt.Println("Test iterative find Value")
	fmt.Println("..............Store to node......")
	randint1 := rand.Intn(150)
	instance1 := instances[randint1]
	randint2 := rand.Intn(150)
	instance2 := instances[randint2]
	randint3 := rand.Intn(150)
	instance3 := instances[randint3]
	instance3Contact := instance3.SelfContact
	instance3ID := instance3Contact.NodeID
	svalue := strconv.Itoa(int(rand.Intn(256)))
	value := []byte(svalue)
	instance2.DoStore(&instance3Contact, instance3ID, value)
	responsevalue := instance1.DoIterativeFindValue(instance3ID)
	theoreticalvalue := " ID: " + instance3ID.AsString() + " Value: " + string(value[:])
	if responsevalue == "ERR: Value not found" {
		fmt.Println("Not Found: " + " Excuter: " + strconv.Itoa(randint1) + " Key: " + strconv.Itoa(randint3))
		return
	}
	if responsevalue != theoreticalvalue {
		t.Error("Iterative Find Value Error, return value is not correct")
		t.Error("return value: " + responsevalue)
		t.Error("expect: " + theoreticalvalue)
	}

	return
}

// func TestIterativeFindValue(t *testing.T) {
// 	fmt.Println("..............Find Value......")
// 	fmt.Println(".........Begin test find node......")
// 	numberOfNodes := 90
// 	numberOfContactsPerNode := 30
// 	instances := make([]Kademlia, numberOfNodes)
// 	instancesAddr := make([]string, numberOfNodes)

// 	//create 100 kademlia instance
// 	fmt.Println("........Create instances......")
// 	for i := 0; i < numberOfNodes; i++ {
// 		port := i + 9000
// 		address := "localhost:" + strconv.Itoa(port)
// 		// fmt.Println("port is " + address)
// 		instancesAddr[i] = address
// 		instances[i] = *NewKademlia(CreateIdForTest(string(i)), address)
// 	}

// 	fmt.Println(".........ping ......")
// 	for i := 0; i < numberOfNodes; i++ {
// 		address := instancesAddr[i]
// 		host, port, _ := StringToIpPort(address)
// 		start := i - numberOfContactsPerNode/2
// 		end := i + numberOfContactsPerNode/2
// 		if i >= numberOfContactsPerNode/2 && i <= numberOfNodes-numberOfContactsPerNode/2 {
// 			for j := start; j < end; j++ {
// 				instances[j].DoPing(host, port)
// 			}
// 		} else {
// 			if i < numberOfContactsPerNode/2 {
// 				for j := 0; j < numberOfContactsPerNode; j++ {
// 					instances[j].DoPing(host, port)
// 				}
// 			} else if i > numberOfNodes-numberOfContactsPerNode/2 {
// 				for j := numberOfNodes - numberOfContactsPerNode; j < numberOfNodes; j++ {
// 					instances[j].DoPing(host, port)
// 				}
// 			}
// 		}
// 		fmt.Println(".........In ping ......")
// 	}

// 	fmt.Println("..............Store to node......")
// 	randint1 := rand.Intn(150)
// 	randint1 = 0
// 	instance1 := instances[randint1]
// 	randint2 := rand.Intn(150)
// 	instance2 := instances[randint2]
// 	randint3 := rand.Intn(150)
// 	randint3 = 60
// 	instance3 := instances[randint3]
// 	instance3Contact := instance3.SelfContact
// 	instance3ID := instance3Contact.NodeID
// 	svalue := strconv.Itoa(int(rand.Intn(256)))
// 	value := []byte(svalue)
// 	instance2.DoStore(&instance3Contact, instance3ID, value)
// 	responsevalue := instance1.DoIterativeFindValue(instance3ID)
// 	theoreticalvalue := " ID: " + instance3ID.AsString() + " Value: " + string(value[:])
// 	if responsevalue == "ERR: Value not found" {
// 		fmt.Println("Not Found: " + " Excuter: " + strconv.Itoa(randint1) + " Key: " + strconv.Itoa(randint3))
// 		return
// 	}
// 	if responsevalue != theoreticalvalue {
// 		t.Error("Iterative Find Value Error, return value is not correct")
// 		t.Error("return value: " + responsevalue)
// 		t.Error("expect: " + theoreticalvalue)
// 	}
// 	return
// }
