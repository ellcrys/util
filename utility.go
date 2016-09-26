package util

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	r "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"github.com/ugorji/go/codec"
)

func init() {
	r.Seed(time.Now().UnixNano())
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Convenient function for fmt.Println.
// Useful when you already have util package imported in current file
func Println(any ...interface{}) {
	fmt.Println(any...)
}

// Get UUID v4 string
func UUID4() string {
	return uuid.NewV4().String()
}

// sha1 hashing
func Sha1(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// decode json string to map
func DecodeJSONToMap(str string) (map[string]interface{}, error) {
	var dat map[string]interface{}
	if err := json.Unmarshal([]byte(str), &dat); err != nil {
		return map[string]interface{}{}, err
	}
	return dat, nil
}

// get random string of fixed length
func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[r.Intn(len(letterBytes))]
	}
	return string(b)
}

// Read n bytes from a pipe and pass bytes read to a callback. If an error occurs
// error is passed to the callback. The callback signature is:
// Func(err error, bs []byte, done bool).
func ReadReader(reader io.Reader, nBytes int, cb func(err error, bs []byte, done bool) bool) {
	r := bufio.NewReader(reader)
	buf := make([]byte, 0, nBytes)
	for {
		n, err := r.Read(buf[:cap(buf)])
		buf = buf[:n]
		if n == 0 {
			if err == nil {
				continue
			}
			if err == io.EOF {
				break
			}
			if cb(err, buf, false) == false {
				return
			}
			break
		}

		// process buf
		if err != nil && err != io.EOF {
			if cb(err, buf, false) == false {
				return
			}
		}

		if cb(err, buf, false) == false {
			return
		}
	}

	cb(nil, buf, true)
}

// cast to map
func Map(m interface{}) map[string]interface{} {
	return m.(map[string]interface{})
}

// Convert stringified JSON array to slice of string.
// JSON array must contain only string values
func JSONToSliceString(jsonStr string) ([]string, error) {
	var data []string
	d := json.NewDecoder(strings.NewReader(jsonStr))
	d.UseNumber()
	if err := d.Decode(&data); err != nil {
		return data, errors.New("unable to parse json string")
	}
	return data, nil
}

// Convert stringified JSON array to slice of maps.
// JSON array must contain only maps
func JSONToSliceOfMap(jsonStr string) ([]map[string]interface{}, error) {
	var data []map[string]interface{}
	d := json.NewDecoder(strings.NewReader(jsonStr))
	d.UseNumber()
	if err := d.Decode(&data); err != nil {
		return data, errors.New("unable to parse json string")
	}
	return data, nil
}

// Convert a byte array to string
func ByteArrToString(byteArr []byte) string {
	return fmt.Sprintf("%s", byteArr)
}

// Read files from /tests/fixtures/ directory
func ReadFromFixtures(path string) string {
	absPath, _ := filepath.Abs(path)
	dat, err := ioutil.ReadFile(absPath)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s", dat)
}

// generate random numbers between a range
func RandNum(min, max int) int {
	s1 := r.NewSource(time.Now().UnixNano())
	r1 := r.New(s1)
	return r1.Intn(max-min) + min
}

// Generate an id to be used as a stone id.
func NewID() string {
	curTime := int(time.Now().Unix())
	id := fmt.Sprintf("%s:%d", UUID4(), curTime)
	return Sha1(id)
}

// Given a slice strings or a slice of interface{} where interface{}
// must be strings. It checks to see if a string is
// contained in the slice.
func InStringSlice(list interface{}, val string) bool {
	switch v := list.(type) {
	case []interface{}:
		for _, s := range v {
			if s.(string) == val {
				return true
			}
		}
		break
	case []string:
		for _, s := range v {
			if s == val {
				return true
			}
		}
	default:
		panic("unsupported type")
	}
	return false
}

// Check whether a regex pattern matches an item in
// a string only slice
func InStringSliceRx(strs []string, pattern string) bool {
	for _, str := range strs {
		if match, _ := regexp.MatchString(pattern, str); match {
			return true
		}
	}
	return false
}

// Checks if a key exists in a map
func HasKey(m map[string]interface{}, key string) bool {
	for k, _ := range m {
		if k == key {
			return true
		}
	}
	return false
}

// Checks that a value type is string
func IsStringValue(any interface{}) bool {
	switch any.(type) {
	case string:
		return true
	default:
		return false
	}
}

// Get all the keys of a map
func GetMapKeys(m map[string]interface{}) []string {
	mk := make([]string, len(m))
	i := 0
	for key, _ := range m {
		mk[i] = key
		i++
	}
	return mk
}

// checks that a variable value type is a map of any value
func IsMapOfAny(any interface{}) bool {
	switch any.(type) {
	case map[string]interface{}:
		return true
		break
	default:
		return false
		break
	}
	return false
}

// checks that a variable value type is a slice
func IsSlice(any interface{}) bool {
	switch any.(type) {
	case []interface{}:
		return true
		break
	default:
		return false
		break
	}
	return false
}

// checks that a slice contains map[string]interface{} type
func ContainsOnlyMapType(s []interface{}) bool {
	for _, v := range s {
		switch v.(type) {
		case map[string]interface{}:
			continue
			break
		default:
			return false
		}
	}
	return true
}

// Checks if a slice contains only string values
func IsSliceOfStrings(s []interface{}) bool {
	for _, v := range s {
		switch v.(type) {
		case string:
			continue
			break
		default:
			return false
		}
	}
	return true
}

// convert a unix time to time object
func UnixToTime(i int64) time.Time {
	return time.Unix(i, 0)
}

// check whether the value passed is int, float64, float32 or int64
func IsNumberValue(val interface{}) bool {
	switch val.(type) {
	case int, int64, float32, float64:
		return true
	default:
		return false
	}
}

// checks whether the value passed is an integer
func IsInt(val interface{}) bool {
	switch val.(type) {
	case int, int64:
		return true
	default:
		return false
	}
}

// checks whether the value passed is a json.Number type
func IsJSONNumber(val interface{}) bool {
	switch val.(type) {
	case json.Number:
		return true
	default:
		return false
	}
}

// cast int value to float64
func IntToFloat64(num interface{}) float64 {
	switch v := num.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		panic("failed to cast unsupported type to float64")
	}
}

// converts int, float32 and float64 to int64
func ToInt64(num interface{}) int64 {
	switch v := num.(type) {
	case int:
		return int64(v)
		break
	case int64:
		return v
		break
	case float64:
		return int64(v)
		break
	case string:
		val, _ := strconv.ParseInt(v, 10, 64)
		return val
		break
	default:
		panic("type is unsupported")
	}
	return 0
}

// get environment variable or return a default value when no set
func Env(key, defStr string) string {
	val := os.Getenv(key)
	if val == "" && defStr != "" {
		return defStr
	}
	return val
}

// check if a map is empty
func IsMapEmpty(m map[string]interface{}) bool {
	return len(GetMapKeys(m)) == 0
}

// converts int to string
func IntToString(v int64) string {
	return fmt.Sprintf("%d", v)
}

// Given a map, it returns a json string representation of it
func MapToJSON(m map[string]interface{}) (string, error) {
	bs, err := json.Marshal(&m)
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

// Given a json string, it decodes it into a map
func JSONToMap(jsonStr string) (map[string]interface{}, error) {
	var data map[string]interface{}
	d := json.NewDecoder(strings.NewReader(jsonStr))
	d.UseNumber()
	if err := d.Decode(&data); err != nil {
		return make(map[string]interface{}), errors.New("unable to parse json string")
	}
	return data, nil
}

// Get the encoded payload from a JWS token
func GetJWSPayload(token string) (string, error) {
	var parts = strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("parameter is not a valid token")
	}
	return parts[1], nil
}

// Read and decode json file
func ReadJSONFile(f string) (map[string]interface{}, error) {

	var key map[string]interface{}

	// load file
	data, err := ioutil.ReadFile(f)
	if err != nil {
		return key, errors.New("failed to load file: " + f)
	}

	// parse file to json
	jsonData, err := DecodeJSONToMap(string(data))
	if err != nil {
		return key, errors.New("failed to decode file: " + f)
	}

	return jsonData, nil
}

// Return all the ip chains of the request.
// The first ip is the remote address and the
// rest are extracted from the x-forwarded-for header
func GetIPs(req *http.Request) []string {

	var ips []string
	var remoteAddr = req.RemoteAddr
	if remoteAddr != "" {
		ipParts := strings.Split(remoteAddr, ":")
		ips = append(ips, ipParts[0])
	}

	// fetch ips in x-forwarded-for header
	var xForwardedFor = strings.TrimSpace(req.Header.Get("x-forwarded-for"))
	if xForwardedFor != "" {
		xForwardedForParts := strings.Split(xForwardedFor, ", ")
		for _, ip := range xForwardedForParts {
			if !InStringSlice(ips, ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// Create an http GET request
func NewGetRequest(url string, headers map[string]string) (*http.Response, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, strings.NewReader(""))
	for key, val := range headers {
		req.Header.Set(key, val)
	}
	return client.Do(req)
}

// Create a http POST request
func NewPostRequest(url, body string, headers map[string]string) (*http.Response, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	for key, val := range headers {
		req.Header.Set(key, val)
	}
	return client.Do(req)
}

// Given a float value, it returns a full
// string representation of the value
func FloatToString(floatVal float64, precision int) string {
	var v big.Float
	v.SetFloat64(floatVal)
	return v.Text('f', precision)
}

// Encode a slice of bytes using messagepack
func MsgPackEncode(d []byte) ([]byte, error) {
	var b []byte = make([]byte, 0, len(d))
	var h codec.Handle = new(codec.JsonHandle)
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, h)
	var err error = enc.Encode(d)
	return b, err
}

// Decode a slice of messagepack bytes
func MsgPackDecode(msgEnc []byte) ([]byte, error) {
	var d []byte
	var h codec.Handle = new(codec.JsonHandle)
	var dec *codec.Decoder = codec.NewDecoderBytes(msgEnc, h)
	err := dec.Decode(&d)
	return d, err
}

// Given a slice of string regex patterns, it will try to find the
// pattern that matches a given match string. Returns the matching pattern
// or an empty string
func StringSliceMatchString(strPatterns []string, strToMatch string) string {
	for _, pat := range strPatterns {
		if match, _ := regexp.MatchString(pat, strToMatch); match {
			return pat
		}
	}
	return ""
}

// Convert a json.Number to Int64. Panics if error occurs
func JSONNumberToInt64(val interface{}) int64 {
	switch v := val.(type) {
	case json.Number:
		num, err := v.Int64()
		if err != nil {
			panic("JSONNumberToInt64: " + err.Error())
		}
		return num
		break
	default:
		panic("JSONNumberToInt64: unknown type. Expects json.Number")
	}
	return 0
}

// convert struct or map to json
func ToJSON(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

// convert json to struct or map
func FromJSON(data []byte, container interface{}) error {
	return json.Unmarshal(data, container)
}
