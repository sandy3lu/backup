package main

import (
	"net"
	"strconv"
	"fmt"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"os/exec"
	"flag"
	"path/filepath"
	"os"
	"strings"
	"path"
	"bytes"
)

const (
	// DefaultServerPort is the default listening port for the fabric-ca server
	DefaultServerPort = 2000

	// DefaultServerAddr is the default listening address for the fabric-ca server
	DefaultServerAddr = "0.0.0.0"
)

var basedir string

func changeDir(){

	exedir := path.Join(basedir,"admin")
	//1 change dir
	//cmd := exec.Command("ls")
	err:=os.Chdir(exedir)
	if err!= nil {
		fmt.Println(err)
		os.Exit(3) //其中执行Exit后程序会直接退出，defer函数不会执行
	}

}

func createResponse(w http.ResponseWriter,success bool, result enrollmentResponseNet,errMsg string){
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	var response Response
	if errMsg!="" {
		response = Response{
			Success:  success,
			Result:   result,
			Errors:  []ResponseMessage{ResponseMessage{404,errMsg}},

		}
	}else{
		response = Response{
			Success:  success,
			Result:   result,
			Errors:  []ResponseMessage{},

		}
	}

	err := enc.Encode(response)
	if err != nil {
		fmt.Println("RegisterServer %s",  err)
	}
}

func RegisterServer(w http.ResponseWriter, req *http.Request) {

	//userID:=req.Header.Get("username")
	//secret:=req.Header.Get("userpad")

	respNil := enrollmentResponseNet{Cert: "", Key:""}

		reqBody, err := ioutil.ReadAll(req.Body)
		if err != nil {
			createResponse(w,false,respNil,err.Error())
			return
		}
		req.Body.Close()
		inputS:=string(reqBody)//username=ttt&userpad=test&userpad=test
		kvpairs:=strings.Split(inputS,"&")
		if len(kvpairs)<2{
			createResponse(w,false,respNil,"not enough input parameters")
			return
		}
		var userID, secret string

		kv1:=strings.SplitAfter(kvpairs[0],"=")
		if kv1[0]=="username="{
			userID = kv1[1]
		}else{//userpad
			secret=kv1[1]
		}
		kv1=strings.Split(kvpairs[1],"=")
		if kv1[0]=="username="{
			userID = kv1[1]
		}else{//userpad
			secret=kv1[1]
		}


		// Parse request body
		//var reqJ RegistrationRequest
		//err = json.Unmarshal(reqBody, &reqJ)
		//if err != nil {
		//	createResponse(w,false,respNil,err.Error())
		//	return
		//}

		//secret:=reqJ.Secret
		//userID:=reqJ.Name


	changeDir()
	//registerStr := fmt.Sprintf("--id.name %s --id.affiliation org1.department1 --id.type user --id.secret %s",userID, secret)
	//2 call CA client to register 各个参数都要单独写
	cmd := exec.Command("fabric-ca-client","register","--id.name", userID,"--id.affiliation", "org1.department1","--id.type", "user" ,"--id.secret",secret)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	//创建获取命令输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		createResponse(w,false,respNil,err.Error())
		return
	}
	//执行命令
	if err := cmd.Start(); err != nil {
		createResponse(w,false,respNil,err.Error())
		return
	}
	//读取所有输出
	bytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		createResponse(w,false,respNil,err.Error())
		return
	}

	if err := cmd.Wait(); err != nil {

		createResponse(w,false,respNil,stderr.String())
		return
	}

	fmt.Println("register OK!", string(bytes))

	changeDir()
		//3 call CA client to enroll
		setEnv:= path.Join(basedir,userID,"msp")

		enrollStr:=fmt.Sprintf("http://%s:%s@localhost:7054", userID,secret)
		cmd = exec.Command("fabric-ca-client", "enroll","-u",enrollStr,"-M",setEnv)
		cmd.Stderr = &stderr
		//创建获取命令输出管道
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			createResponse(w,false,respNil,err.Error())
			return
		}
		//执行命令
		if err := cmd.Start(); err != nil {
			createResponse(w,false,respNil,err.Error())
			return
		}
		//读取所有输出
		bytes, err = ioutil.ReadAll(stdout)
		if err != nil {
			createResponse(w,false,respNil,err.Error())
			return
		}
		if err := cmd.Wait(); err != nil {
			createResponse(w,false,respNil,stderr.String())
			return
		}

		// write response
		var contentkey []byte
		files,err:=ioutil.ReadDir(path.Join(setEnv,"keystore"))
		var filename string
		for _, file := range files {
			if file.IsDir() {
				continue
			} else {
				filename = file.Name()
				if strings.Contains(filename,"_sk"){
					contentkey,err=ioutil.ReadFile(path.Join(setEnv,"keystore",filename))
					if err!=nil{
						createResponse(w,false,respNil,err.Error())
						return
					}
					break
				}

			}
		}


		contentCert,err:=ioutil.ReadFile(path.Join(setEnv,"signcerts","cert.pem"))
		if err== nil {
				// Send the response with the cert and the server info
				resp := enrollmentResponseNet{Cert: string(contentCert), Key:string(contentkey)}

				createResponse(w,true,resp,"")
				return
		} else {

				createResponse(w,false,respNil,err.Error())
		}



}

func main() {


	currentdir, err := filepath.Abs(filepath.Dir(os.Args[0]))

	flag.StringVar(&basedir, "basedir", currentdir, "base dir for fabric clinet CA")

	flag.Parse()
	fmt.Println("basedir:", basedir)

	// The current listener for this server
	http.HandleFunc("/", RegisterServer)
	// addr = host:port
	addr := net.JoinHostPort(DefaultServerAddr, strconv.Itoa(DefaultServerPort))

	addrStr := fmt.Sprintf("http://%s", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("TCP listen failed for %s: %s", addrStr, err)
		return
	}

	err = http.Serve(listener, nil)
	if err != nil {

		listener.Close()
	}
}
