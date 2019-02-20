package main

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alyu/configparser"
	"github.com/antchfx/xmlquery"
	"github.com/rahulsahay144/soup"

	b64 "encoding/base64"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

var outputformat = "json"
var awsconfigfile = "~/.aws/credentials"
var sslverification = true

// SAML Identity URL
var idpentryurl = ""

// Form POST Url
var idpauthformsubmiturl = ""

// Set Company proxy
var httpProxy = ""

func main() {
	soup.Header("User-Agent", `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:34.0) Gecko/20100101 Firefox/34.0","Accept-Encoding": "gzip, deflate, sdch`)

	// Get Username and Password from cli
	username, password := getUserCredentials()
	//fmt.Printf("Username: %s, Password: %s\n", username, password)
	fmt.Println()
	fmt.Println("Please wait while we log you in.......")

	proxy := fmt.Sprintf(httpProxy, username, password)
	//fmt.Printf("Proxy %s\n", proxy)
	os.Setenv("https_proxy", proxy)

	data := url.Values{}
	data.Set("username", username)
	data.Add("password", password)
	data.Add("login-form-type", "pwd")

	response, err := soup.Post(idpauthformsubmiturl, data.Encode())
	//fmt.Printf("%s\n", response2)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}

	response, err = soup.Get(idpentryurl)
	//fmt.Printf("%s\n", response)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}

	assertion := ""
	doc := soup.HTMLParse(response)
	inputs := doc.FindAll("input")
	for _, input := range inputs {
		//fmt.Println(input.Attrs()["name"], "| Name :", input.Attrs()["value"])

		if input.Attrs()["name"] == "SAMLResponse" {
			assertion = input.Attrs()["value"]
		}
	}

	//fmt.Println("SAMLResponse :", assertion)
	//fmt.Println()

	if assertion == "" {
		fmt.Printf("-----------------------------------------------------")
		fmt.Printf("Error page from WebSEAL")
		//fmt.Printf(string(doc))
		fmt.Printf("-----------------------------------------------------")
		fmt.Printf("Response did not contain a valid SAML assertion")
		fmt.Printf("Please check your userid and password and try again")
		fmt.Printf("If the problem persists, please contact your administrator")
		os.Exit(1)
	}

	// Decode....
	decodedAssertion, _ := b64.StdEncoding.DecodeString(assertion)
	//fmt.Println("SAMLResponse :", string(decodedAssertion))

	xmldoc, err := xmlquery.Parse(strings.NewReader(string(decodedAssertion)))
	roleNode := xmlquery.FindOne(xmldoc, "//saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']")
	//fmt.Println()

	awsRoles := roleNode.SelectElements("saml:AttributeValue")

	awsRoleMap := make(map[int]string)
	i := 0
	for _, role := range awsRoles {
		//fmt.Println("Name :", role.InnerText())
		role := role.InnerText()
		chunks := strings.Split(role, ",")

		newawsrole := chunks[1] + "," + chunks[0]
		awsRoleMap[i] = newawsrole
		i++
	}

	fmt.Println("Please choose the role you would like to assume:")
	fmt.Println()

	for key, value := range awsRoleMap {
		//fmt.Println("Key:", key, "Value:", value)
		fmt.Println("[", key, "]: ", strings.Split(value, ",")[1])
	}

	//reader := bufio.NewReader(os.Stdin)
	fmt.Println()
	fmt.Print("Selection: ")

	var selectedroleindex int
	fmt.Scanf("%d", &selectedroleindex)

	roleArn := strings.Split(awsRoleMap[selectedroleindex], ",")[1]
	principalArn := strings.Split(awsRoleMap[selectedroleindex], ",")[0]

	fmt.Println("Selected RoleArn : ", roleArn)
	fmt.Println("Selected PrincipalArn : ", principalArn)

	// assume role
	sess := session.Must(session.NewSession())

	// sess := session.Must(session.NewSessionWithOptions(session.Options{
	// 	SharedConfigState: session.SharedConfigEnable,
	// }))

	svc := sts.New(sess)
	token, err := svc.AssumeRoleWithSAML(
		&sts.AssumeRoleWithSAMLInput{
			PrincipalArn:    &principalArn,
			RoleArn:         &roleArn,
			SAMLAssertion:   &assertion,
			DurationSeconds: aws.Int64(3600),
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "STS AssumeRoleWithSAML() error: %s\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println()
	fmt.Println("============")
	fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", *token.Credentials.AccessKeyId)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", *token.Credentials.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", *token.Credentials.SessionToken)
	fmt.Println("============")
	fmt.Println()

	// Write the AWS STS token into the AWS credential file
	filename, _ := expand(awsconfigfile)
	//fmt.Println("Config File name : ", filename)

	// set a custom delimiter to be used for key/value seperation
	configparser.Delimiter = "="
	config, err := configparser.Read(filename)
	if err != nil {
		log.Fatal(err)
	}

	// Print the full configuration
	//fmt.Println(config)

	// get a section
	section, err3 := config.Section("saml")
	if err3 != nil {
		//log.Fatal(err3)
		fmt.Println("============ Adding a new SAML section =======================")

		// add a new section and options
		section = config.NewSection("saml")
		section.Add("output", outputformat)
		section.Add("aws_access_key_id", *token.Credentials.AccessKeyId)
		section.Add("aws_secret_access_key", *token.Credentials.SecretAccessKey)
		section.Add("aws_session_token", *token.Credentials.SessionToken)

	} else {
		// set new value
		// var oldValue = section.SetValueFor("aws_access_key_id", *token.Credentials.AccessKeyId)
		// fmt.Printf("aws_access_key_id=%s, old value=%s\n", section.ValueOf("aws_session_token"), oldValue)

		// set new value
		section.SetValueFor("aws_access_key_id", *token.Credentials.AccessKeyId)
		section.SetValueFor("aws_secret_access_key", *token.Credentials.SecretAccessKey)
		section.SetValueFor("aws_session_token", *token.Credentials.SessionToken)

		// delete option
		// oldValue = section.Delete("DefaultOperationRedoProblemAction")
		// fmt.Println("Deleted DefaultOperationRedoProblemAction: " + oldValue)

		// // add new options
		// section.Add("innodb_buffer_pool_size", "64G")
		// section.Add("innodb_buffer_pool_instances", "8")
	}

	// save the new config. the original will be renamed to /etc/config.ini.bak
	err = configparser.Save(config, filename)
	if err != nil {
		log.Fatal(err)
	}

	// Give the user some basic info as to what has just happened
	fmt.Println("\n\n----------------------------------------------------------------")
	fmt.Printf("Your new access key pair has been stored in the AWS configuration file %s under the saml profile.", filename)
	fmt.Println()
	fmt.Printf("Note that it will expire at %s.", *token.Credentials.Expiration)
	fmt.Println()
	//fmt.Printf("The temporary creds are established at %s.",  *token.Credentials.Expiration  .format(token.get('ResponseMetadata').get('HTTPHeaders').get('date')))
	fmt.Println("After this time, you may safely rerun this script to refresh your access key pair.")
	fmt.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).")
	fmt.Println("----------------------------------------------------------------")
	fmt.Println()

	// Test Credentials
	sess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Profile:           "saml",
	}))

	svc = sts.New(sess)

	//svc = sts.New(sess, &aws.Config{Credentials: *token.Credentials})

	input := &sts.GetCallerIdentityInput{}

	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

func getUserCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		// fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
}
