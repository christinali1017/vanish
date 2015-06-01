package kademlia

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
	"sss"
	// "strconv"
	"strings"
	"time"
)

const Hour time.Duration = 1500 * time.Minute

type VanashingDataObject struct {
	AccessKey  int64
	Ciphertext []byte
	NumberKeys byte
	Threshold  byte
}

func GenerateRandomCryptoKey() (ret []byte) {
	for i := 0; i < 32; i++ {
		ret = append(ret, uint8(mathrand.Intn(256)))
	}
	return
}

func GenerateRandomAccessKey() (accessKey int64) {
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	accessKey = r.Int63()
	return
}

func CalculateSharedKeyLocations(accessKey int64, count int64) (ids []ID) {
	r := mathrand.New(mathrand.NewSource(accessKey))
	ids = make([]ID, count)
	for i := int64(0); i < count; i++ {
		for j := 0; j < IDBytes; j++ {
			ids[i][j] = uint8(r.Intn(256))
		}
	}
	return
}

func encrypt(key []byte, text []byte) (ciphertext []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext = make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return
}

func decrypt(key []byte, ciphertext []byte) (text []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext is not long enough")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}

func VanishData(kadem Kademlia, data []byte, numberKeys byte,
	threshold byte, validPeriod int) (vdo VanashingDataObject) {
	k := GenerateRandomCryptoKey()
	ciphertext := encrypt(k, data)
	splitKeysMap, err := sss.Split(numberKeys, threshold, k)
	vdo = *new(VanashingDataObject)

	if err != nil {
		return vdo
	}

	accessKey := GenerateRandomAccessKey()
	randomSequence := CalculateSharedKeyLocations(accessKey, int64(numberKeys))

	//store keys
	for i := 0; i < len(randomSequence); i++ {
		//all := append([]byte{k}, v...)
		k := byte(i + 1)
		v := splitKeysMap[k]
		all := append([]byte{k}, v...)
		// fmt.Print("#########################Vanish key is: ")
		// fmt.Printf("%x", string(k))
		// fmt.Print("#########################Store Value is: ")
		// fmt.Printf("%x", string(v[:]))
		// fmt.Println("beforem interative store length:" + strconv.Itoa(len(all)))
		kadem.DoIterativeStore(randomSequence[i], all)
	}

	if (validPeriod > 8) {
		ticker := time.NewTicker(Hour * 8)
		stop := make(chan int)
		go func() {
		    for {
		       select {
		        case <- ticker.C:
		        	// republish
	        		randomSequence := CalculateSharedKeyLocations(accessKey, int64(numberKeys))
					//store keys
					for i := 0; i < len(randomSequence); i++ {
						//all := append([]byte{k}, v...)
						k := byte(i + 1)
						v := splitKeysMap[k]
						all := append([]byte{k}, v...)
						kadem.DoIterativeStore(randomSequence[i], all)
					}

					validPeriod = validPeriod - 8

					//after valid time period the data expires
					if validPeriod <= 0 {
						stop <- 1
					}
		            
		        case <- stop:
		            ticker.Stop()
		            return
		        }
		    }
	 	}()
	}

	//create vdo object

	vdo.AccessKey = accessKey
	vdo.Ciphertext = ciphertext
	vdo.NumberKeys = numberKeys
	vdo.Threshold = threshold
	return
}

func UnvanishData(kadem Kademlia, vdo VanashingDataObject) (data []byte) {
	accessKey := vdo.AccessKey
	ciphertext := vdo.Ciphertext
	numberOfKeys := vdo.NumberKeys
	threShold := vdo.Threshold
	splitKeysMap := make(map[byte][]byte)

	randomSequence := CalculateSharedKeyLocations(accessKey, int64(numberOfKeys))

	//store keys
	for i := 0; i < len(randomSequence); i++ {
		resString := kadem.DoIterativeFindValue(randomSequence[i])
		indexV := strings.Index(resString, "Value:")
		// fmt.Println("Unvanish" + strconv.Itoa(i))
		// fmt.Println("Value is:" + resString)

		if indexV != -1 {
			// fmt.Println("Come here:" + strconv.Itoa(i))
			indexV = indexV + 7
			resString = resString[indexV:]
			// fmt.Println("````````````````````````````````RES LENGTH" + strconv.Itoa(len(resString)))
			if len(resString) > 1 {
				resultByte := []byte(resString)
				v := resultByte[1:]
				k := resultByte[0:1]
				// fmt.Print("#########################UnVanish key is: ")
				// fmt.Printf("%x", string(k[:]))
				for inde := range k {
					key := k[inde]
					//fmt.Print("#########################What is the key here: ")
					//fmt.Printf("%x", string(key))
					//fmt.Print("#########################Put in split: ")
					//fmt.Printf("%x", string(v[:]))
					splitKeysMap[byte(key)] = v
					//fmt.Println("splitKeysMap size change to:" + strconv.Itoa(int(len(splitKeysMap))))

					break
				}
			}
			if int64(len(splitKeysMap)) == int64(threShold) {
				break
			}

		} else {
			continue
		}
	}
	//fmt.Println("How many we have in splitKeysMap:" + strconv.Itoa(int(len(splitKeysMap))))
	//fmt.Println("How many we have for threShold:" + strconv.Itoa(int(threShold)))

	if int64(len(splitKeysMap)) >= int64(threShold) {
		//fmt.Println("How many we have:" + strconv.Itoa(int(len(splitKeysMap))))
		secretKey := sss.Combine(splitKeysMap)
		data = decrypt(secretKey, ciphertext)
		fmt.Print("=================Data is in hex: ")
		fmt.Printf("%x", string(data[:]))
		fmt.Print("=================Data is: ")
		fmt.Print(data)

		return
	}

	return
}
